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

static int bb_socketio_recv_complete(struct bb_session *bbs) {
	// minimal = X:::
               if (bbs->request.sio_post_buf_size < 4) return -1;
                // multipart message ?
                if (bbs->request.sio_post_buf[0] == '\xef' && bbs->request.sio_post_buf[1] == '\xbf' && bbs->request.sio_post_buf[2] == '\xbd') {
                        char *ptr = bbs->request.sio_post_buf;
                        char *watermark = ptr+bbs->request.sio_post_buf_size;
                        while(ptr < watermark) {
                                if (*ptr++ != '\xef') return -1;
                                if (ptr+1 > watermark) return -1;
                                if (*ptr++ != '\xbf') return -1;
                                if (ptr+1 > watermark) return -1;
                                if (*ptr++ != '\xbd') return -1;
                                if (ptr+1 > watermark) return -1;
                                char *base_of_num = ptr;
                                size_t end_of_num = 0;
                                while(*ptr >= '0' && *ptr<='9') {
                                        if (ptr+1 > watermark) return -1;
                                        end_of_num++;
                                        ptr++;
                                }
                                size_t part_len = bb_str2num(base_of_num, end_of_num);
                                if (*ptr++ != '\xef') return -1;
                                if (ptr+1 > watermark) return -1;
                                if (*ptr++ != '\xbf') return -1;
                                if (ptr+1 > watermark) return -1;
                                if (*ptr++ != '\xbd') return -1;
                                if (ptr+1 > watermark) return -1;
                                if (ptr+part_len > watermark) return -1;
                                if (bb_socketio_message(bbs->sio_session, ptr, part_len))
                                        return -1;
                                ptr+=part_len;
                        }
                }
                else {
                        if (bb_socketio_message(bbs->sio_session, bbs->request.sio_post_buf, bbs->request.sio_post_buf_size))
                                return -1;
                }

	return 0;
}

static int bb_socketio_recv_body(struct bb_session *bbs, char *buf, size_t len) {
	char *new_buf = realloc(bbs->request.sio_post_buf, bbs->request.sio_post_buf_size+len);
        if (!new_buf) {
                bb_error("realloc()");
        	return -1;
        }
        bbs->request.sio_post_buf = new_buf;
        memcpy(bbs->request.sio_post_buf+bbs->request.sio_post_buf_size, buf, len);
        bbs->request.sio_post_buf_size+=len;
	return 0;
}


int bb_socketio_message(struct bb_session *bbs, char *buf, size_t len) {
	if (len == 3 && buf[1] == ':' && buf[2] == ':') return 0;
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
	"Content-Length: 64\r\n"
	"Access-Control-Allow-Origin: null\r\n"
	"Access-Control-Allow-Credentials: true\r\n"
	"Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n"
	"Access-Control-Max-Age: 3600\r\n\r\n";

static const struct bb_http_header handshake_spdy_headers[] = {
	{ .key = "content-type", .keylen = 12, .value = "text/plain", .vallen = 10 },
	{ .key = "connection", .keylen = 10, .value = "keep-alive", .vallen = 10 },
	{ .key = "content-length", .keylen = 14, .value = "52", .vallen = 2 },
	{ .key = "access-control-allow-origin", .keylen = 27, .value = "null", .vallen = 4 },
	{ .key = "access-control-allow-credentials", .keylen = 32, .value = "true", .vallen = 4 },
	{ .key = "access-control-allow-methods", .keylen = 28, .value = "POST, GET, OPTIONS", .vallen = 18 },
	{ .key = "access-control-max-age", .keylen = 22, .value = "3600", .vallen = 4 },
};

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

static const char message_headers[] =
	"HTTP/1.1 200 OK\r\n"
	"Content-Type: text/plain; charset=UTF-8\r\n"
	"Access-Control-Allow-Origin: *\r\n"
	"Access-Control-Allow-Credentials: true\r\n"
	"Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n"
	"Access-Control-Max-Age: 3600\r\n"
	"Content-Length: ";

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

static int socketio_heartbeat(struct bb_session *bbs) {
	if (bb_websocket_reply(bbs, "2::", 3)) {
		return 0;
	}
	bb_session_reset_timer(bbs, 20, socketio_heartbeat);
	return -1;
}


int bb_manage_socketio(struct bb_session *bbs, char *method, size_t method_len, char *url, size_t url_len) {

	char *query_string = memchr(url, '?', url_len);
	if (query_string) {
		url_len = query_string-url;
	}

	fprintf(stderr,"SOCKET.IO %.*s %.*s\n", method_len, method, url_len, url);

	// handshake
	if (url_len == 13) {

		char handshake[36+3+3+1+21];

		uuid_t *session_uuid = (uuid_t *) &bbs->uuid_part1; 
		uuid_unparse(*session_uuid, handshake);

		if (bbs->stream_id > 0) {
			// only websockets are supported under SPDY 
			char *supported = "websocket";
                        memcpy(handshake+36, ":30:60:", 7);
                        memcpy(handshake+36+7, supported, 9);
			if (bb_spdy_raw_send_headers(bbs, 0, 7, handshake_spdy_headers, "200", "HTTP/1.1", 0)) return -1;
			if (bb_spdy_send_body(bbs, handshake, 52)) return -1;
			if (bb_spdy_send_end(bbs)) return -1;
		}
		else {
			char *supported = "websocket,xhr-polling";
			memcpy(handshake+36, ":30:60:", 7);
			memcpy(handshake+36+7, supported, 21);
        		if (bb_wq_push(bbs, (char *)handshake_headers, strlen(handshake_headers), 0)) return -1;
        		if (bb_wq_push_copy(bbs, handshake, 64, BB_WQ_FREE)) return -1;
			// do not close as smart browser could use keep-alive
        		//if (bb_wq_push_close(bbs)) return -1;
		}

		// mark the session as persistent
		bbs->persistent = 1;
		// do not forward the request to dealers
		bbs->request.no_uwsgi = 1;
        	return 0;

	}
	//websocket/a7b23852-2388-41d7-8f20-8cff5be70e82
	else if (url_len == 13 + 9 + 1 + 36) {
		uuid_t sio_uuid;
                char tmp_uuid[37];
                memcpy(tmp_uuid, url+13 + 9 + 1, 36);
                tmp_uuid[36] = 0;
                if (uuid_parse(tmp_uuid, sio_uuid)) return -1;
                struct bb_session *persistent_bbs = bb_sht_get((char *)sio_uuid);

                if (!persistent_bbs) return -1;
                // skip non-persistent connection
                if (!persistent_bbs->persistent) return -1;
                // skip different vhost
                if (persistent_bbs->vhost != bbs->vhost) return -1;

		struct bb_connection *bbc = bbs->connection;
                // close the current session but without freeing the request
                bbs->stealth = 1;
                // ...and map the connection
                persistent_bbs->connection = bbc;
                // set the session as the main one for the connection
                if (!bbc->sessions_head) {
                        bbc->sessions_head = persistent_bbs;
                        bbc->sessions_tail = persistent_bbs;
                }
                else {
			persistent_bbs->conn_prev = NULL;
			persistent_bbs->conn_next = bbc->sessions_head;
			bbc->sessions_head->prev = persistent_bbs;
			bbc->sessions_head = persistent_bbs;
                }

		bbs->connection->func = bb_websocket_func;
                bb_send_websocket_handshake(bbs);
		bb_websocket_reply(bbs, "1::", 3);
		persistent_bbs->sio_connected = 1;
		persistent_bbs->sio_realtime = 1;
		bb_session_reset_timer(persistent_bbs, 20, socketio_heartbeat);
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
		if (!bb_strcmp(method, method_len, "POST",4)) {
			if (!persistent_bbs->sio_connected) return -1;
			if (bb_wq_push(bbs, (char *)post_headers, strlen(post_headers), 0)) return -1;
			//if (bb_wq_push_close(bbs)) return -1;	
			if (bbs->request.parser.content_length != ULLONG_MAX && bbs->request.parser.content_length > 0) {
				bbs->sio_session = persistent_bbs;
				//bbs->sio_bbs = persistent_bbs;
				bbs->request.no_uwsgi = 1;
				// set socket.io hooks
				bbs->recv_body = bb_socketio_recv_body;
				bbs->recv_complete = bb_socketio_recv_complete;
				// do not report session death
				bbs->stealth = 1;
				return 0;
			}
			return -1;	
		}

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
		if (!bb_strcmp(method, method_len, "GET", 3)) {
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

	char *cl = malloc(MAX_CONTENT_LENGTH);
        if (!cl) {
                bb_error("unable to allocate memory for socket.io message: malloc()");
                return -1;
        }
        int chunk_len = snprintf(cl, MAX_CONTENT_LENGTH, "%llu\r\n\r\n", (unsigned long long) len);

	if (bb_wq_push(bbs, (char *)message_headers, strlen(message_headers), 0)) return -1;
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

	if (bbs->sio_realtime) {
		return bb_websocket_reply(bbs, message, len+4);
	}


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
