#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

/*

socket.io management

/socket.io/1/ -> send handshake response using the bb sid, mark the sid as persistent

/socket.io/1/xhr-polling/<sid> -> recover the session id and move the current request to it
parse the body and generate the socket.io/type message

/socket.io/1/websocket/<sid> -> recover the session id and move the current request to it
parse each websocket message twice (one for websocket and one for socket.io format) and generate
the socket.io/type message

*/

static char *find_third_colon(char *buf, size_t len) {
        size_t i;
        int count = 0;
        for(i=0;i<len;i++) {
                if (buf[i] == ':') {
                        count++;
                        if (count == 3) {
                                if ((i+1) > (len-1)) return NULL;
                                return buf+i+1;
                        }
                }
        }
        return NULL;
}


int bb_socketio_message(struct bb_session *bbs, char *buf, size_t len) {
        char *sio_body = find_third_colon(buf, len);
        if (!sio_body) return -1;
        size_t sio_len = len - (sio_body-buf);
        // forward socket.io message to the right session
        switch(buf[0]) {
                case '3':
                        bb_zmq_send_msg(bbs->dealer->identity, bbs->dealer->len, (char *) &bbs->uuid_part1, BB_UUID_LEN, "socket.io/msg", 13, sio_body, sio_len);
                        break;
                case '4':
                        bb_zmq_send_msg(bbs->dealer->identity, bbs->dealer->len, (char *) &bbs->uuid_part1, BB_UUID_LEN, "socket.io/json", 14, sio_body, sio_len);
                        break;
                case '5':
                        bb_zmq_send_msg(bbs->dealer->identity, bbs->dealer->len, (char *) &bbs->uuid_part1, BB_UUID_LEN, "socket.io/event", 15, sio_body, sio_len);
                        break;
                default:
                        fprintf(stderr,"SOCKET.IO MESSAGE TYPE: %c\n", buf[0]);
                        return -1;
        }
        return 0;
}


static const char handshake_headers[] =
	"HTTP/1.1 200 OK\r\n"
	"Content-Type: text/plain\r\n"
	"Connection: keep-alive\r\n"
	"Content-Length: 54\r\n"
	"Access-Control-Allow-Origin: null\r\n"
	"Access-Control-Allow-Credentials: true\r\n"
	"Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n"
	"Access-Control-Max-Age: 3600\r\n\r\n";

static const char post_headers[] =
	"HTTP/1.1 200 OK\r\n"
	"Connection: close\r\n"
	"Content-Type: text/plain\r\n"
	"Access-Control-Allow-Origin: *\r\n"
	"Access-Control-Allow-Credentials: true\r\n"
	"Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n"
	"Access-Control-Max-Age: 3600\r\n"
	"Content-Length: 1\r\n\r\n1";

static const char connected_headers[] =
	"HTTP/1.1 200 OK\r\n"
	"Connection: close\r\n"
	"Content-Type: text/plain; charset=UTF-8\r\n"
	"Access-Control-Allow-Origin: *\r\n"
	"Access-Control-Allow-Credentials: true\r\n"
	"Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n"
	"Access-Control-Max-Age: 3600\r\nContent-Length: 3\r\n\r\n1::";

static const char empty_queue[] = 
	"HTTP/1.1 200 OK\r\n"
	"Content-Type: text/plain; charset=UTF-8\r\n"
	"Access-Control-Allow-Origin: *\r\n"
	"Access-Control-Allow-Credentials: true\r\n"
	"Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n"
	"Access-Control-Max-Age: 3600\r\n"
	"Content-Length: 0\r\n\r\n";

static int socketio_poller(struct bb_session *bbs) {
	struct bb_socketio_message *bbsm = bbs->sio_queue;
        if (bbsm) {
        	if (bb_socketio_send(bbs, bbsm->buf, bbsm->len)) {
                	fprintf(stderr,"unable to deliver message\n");
			return 0;
                }
                bbs->sio_queue = bbsm->next;
                free(bbsm);
		bbs->sio_poller = 0;
                return 1;
	}

	if (bb_wq_push(bbs, (char *)empty_queue, strlen(empty_queue), 0)) return 0;
	if (bb_wq_push_close(bbs)) return 0;
	bb_session_reset_timer(bbs, 60, NULL);
	bbs->sio_poller = 0;
	// leave the session opened
	return 1;	
}


int bb_manage_socketio(struct bb_session *bbs) {
	char *url = bbs->request.headers[0].key;
	size_t url_len = bbs->request.headers[0].keylen;

	char *query_string = memchr(url, '?', url_len);
	if (query_string) {
		url_len = query_string-url;
	}

	fprintf(stderr,"SOCKET.IO %s %.*s\n", http_method_str(bbs->request.parser.method), url_len, url);

	// handshake
	if (url_len == 13) {
		char *supported = "xhr-polling";
		char handshake[36+3+3+1+11];
		uuid_t *session_uuid = (uuid_t *) &bbs->uuid_part1; 
		uuid_unparse(*session_uuid, handshake);
		memcpy(handshake+36, ":60:60:", 7);
		memcpy(handshake+36+7, supported, 11);

        	if (bb_wq_push(bbs, (char *)handshake_headers, strlen(handshake_headers), 0)) return -1;
        	if (bb_wq_push_copy(bbs, handshake, 54, BB_WQ_FREE)) return -1;

		// mark the session as persistent
		bbs->persistent = 1;
		// do not forward the request to dealers
		bbs->request.no_uwsgi = 1;

        	return 0;

	}
	//xhr-polling/a7b23852-2388-41d7-8f20-8cff5be70e82
	else if (url_len == 13 + 11 + 1 + 36) {


		uuid_t sio_uuid;
		char tmp_uuid[37];
		memcpy(tmp_uuid, url+13 + 11 + 1, 36);
		tmp_uuid[36] = 0;
		if (uuid_parse(tmp_uuid, sio_uuid)) return -1;
		struct bb_session *persistent_bbs = bb_sht_get((char *)sio_uuid);
		
		if (!persistent_bbs) return -1;
		// skip non-persistent connection
		if (!persistent_bbs->persistent) return -1;
		// skip different vhost
		if (persistent_bbs->vhost != bbs->vhost) return -1;

		// TODO check for already running pollers...
		
		// sending messages does not require remapping the session
		if (bbs->request.parser.method == HTTP_POST) {
			if (!persistent_bbs->sio_connected) return -1;
			if (bb_wq_push(bbs, (char *)post_headers, strlen(post_headers), 0)) return -1;
			//if (bb_wq_push_close(bbs)) return -1;	
			if (bbs->request.parser.content_length != ULLONG_MAX && bbs->request.parser.content_length > 0) {
				bbs->sio_session = persistent_bbs;
				//bbs->sio_bbs = persistent_bbs;
				bbs->request.no_uwsgi = 1;
				// buffer following data
				bbs->request.sio_post = 1;
				bbs->stealth = 1;
				return 0;
			}
			return -1;	
		}

		//store the current method
		unsigned char request_method = bbs->request.parser.method;

		// is it already the correct session ?
		if (bbs == persistent_bbs) goto ready;

		// ok, prepare for the heavy part:
		// get the current connection
		struct bb_connection *bbc = bbs->connection;
		// close the current session but without freeing the request
		bbs->stealth = 1;
		// ...and map the connection
		persistent_bbs->connection = bbc;
		// append the session to the connection
		if (!bbc->sessions_head) {
                	bbc->sessions_head = persistent_bbs;
                	bbc->sessions_tail = persistent_bbs;
        	}
        	else {
                	bbs->conn_prev = bbc->sessions_tail;
                	bbc->sessions_tail = persistent_bbs;
                	bbs->conn_prev->next = persistent_bbs;
        	}

ready:
		// ok we are ready
		if (request_method == HTTP_GET) {
			// already handshaked, this is a poll
			if (persistent_bbs->sio_connected) {
				// do not forward the request to the dealer
				bbs->request.no_uwsgi = 1;
				struct bb_socketio_message *bbsm = persistent_bbs->sio_queue;
                		if (bbsm) {
                			if (bb_socketio_send(persistent_bbs, bbsm->buf, bbsm->len)) {
                        			fprintf(stderr,"unable to deliver message\n");
                			}
                			persistent_bbs->sio_queue = bbsm->next;
                			free(bbsm);
					return 0;
				}
				// start the poller
				persistent_bbs->sio_poller = 1;
				bb_session_reset_timer(persistent_bbs, 30.0, socketio_poller);
				return 0;
			}
			else {
				if (bb_wq_push(bbs, (char *)connected_headers, strlen(connected_headers), 0)) return -1;
				if (bb_wq_push_close(bbs)) return -1;	
				persistent_bbs->sio_connected = 1;
				// start the sio_timer
				bb_session_reset_timer(persistent_bbs, 60.0, NULL);
				return 0;
			}
		}
	}	

	return -1;
}

int bb_socketio_send(struct bb_session *bbs, char *buf, size_t len) {
	const char *headers = " 200 OK\r\nContent-Type: text/plain; charset=UTF-8\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Max-Age: 3600\r\nContent-Length: ";
	char *cl = malloc(MAX_CONTENT_LENGTH);
        if (!cl) {
                bb_error("unable to allocate memory for socket.io message: malloc()");
                return -1;
        }
        int chunk_len = snprintf(cl, MAX_CONTENT_LENGTH, "%llu\r\n\r\n", (unsigned long long) len);

	bbs->request.http_major = '0' + bbs->request.parser.http_major;
        bbs->request.http_minor = '0' + bbs->request.parser.http_minor;

        if (bb_wq_push(bbs, "HTTP/", 5, 0)) return -1;
        if (bb_wq_push(bbs, &bbs->request.http_major, 1, 0)) return -1;
        if (bb_wq_push(bbs, ".", 1, 0)) return -1;
        if (bb_wq_push(bbs, &bbs->request.http_minor, 1, 0)) return -1;


	if (bb_wq_push(bbs, (char *)headers, strlen(headers), 0)) return -1;
	if (bb_wq_push(bbs, (char *)cl, chunk_len, BB_WQ_FREE)) return -1;

	if (bb_wq_push(bbs, (char *)buf, len, BB_WQ_FREE)) return -1;

	return 0;
}

int bb_socketio_push(struct bb_session *bbs, char type, char *buf, size_t len) {

	char *message = malloc(4 + len);
	if (!message) {
		bb_error("malloc()");
		return -1;
	}	

	message[0] = type;
	message[1] = ':';
	message[2] = ':';
	message[3] = ':';
	
	memcpy(message+4, buf, len);

	struct bb_socketio_message *last_bbsm=NULL,*bbsm = bbs->sio_queue;

	while(bbsm) {
		last_bbsm = bbsm;
		bbsm = bbsm->next;
	}

	bbsm = malloc(sizeof(struct bb_socketio_message));
	if (!bbsm) {
		free(message);
		bb_error("malloc()");
		return -1;
	}
	memset(bbsm, 0, sizeof(struct bb_socketio_message));
	bbsm->buf = message;
	bbsm->len = 4+len;
	if (last_bbsm) {
		last_bbsm->next = bbsm;
	}
	else {
		bbs->sio_queue = bbsm;
	}

	//is a poller attached to the session ?
	if (bbs->sio_poller) {
		ev_feed_event(blastbeat.loop, &bbs->death_timer, EV_TIMER);
	}

	return 0;
}
