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


		const char *hs_headers = " 200 OK\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\nContent-Length: 54\r\nAccess-Control-Allow-Origin: null\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Max-Age: 3600\r\n\r\n";

		bbs->request.http_major = '0' + bbs->request.parser.http_major;
        	bbs->request.http_minor = '0' + bbs->request.parser.http_minor;

        	if (bb_wq_push(bbs->connection, "HTTP/", 5, 0)) return -1;
        	if (bb_wq_push(bbs->connection, &bbs->request.http_major, 1, 0)) return -1;
        	if (bb_wq_push(bbs->connection, ".", 1, 0)) return -1;
        	if (bb_wq_push(bbs->connection, &bbs->request.http_minor, 1, 0)) return -1;
        	if (bb_wq_push(bbs->connection, (char *)hs_headers, strlen(hs_headers), 0)) return -1;
        	if (bb_wq_push_copy(bbs->connection, handshake, 54, 1)) return -1;

		// mark the session as persistent
		bbs->persistent = 1;
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

		// TODO check for already running pollers...
		
		// sending messages does not require remapping the session
		if (bbs->request.parser.method == HTTP_POST) {
			bbs->request.http_major = '0' + bbs->request.parser.http_major;
        		bbs->request.http_minor = '0' + bbs->request.parser.http_minor;

			if (bb_wq_push(bbs->connection, "HTTP/", 5, 0)) return -1;
                	if (bb_wq_push(bbs->connection, &bbs->request.http_major, 1, 0)) return -1;
                	if (bb_wq_push(bbs->connection, ".", 1, 0)) return -1;
                	if (bb_wq_push(bbs->connection, &bbs->request.http_minor, 1, 0)) return -1;

			const char *connected = " 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Max-Age: 3600\r\nContent-Length: 1\r\n\r\n1";
			if (bb_wq_push(bbs->connection, (char *)connected, strlen(connected), 0)) return -1;
			if (bb_wq_push_close(bbs->connection)) return -1;	
			if (bbs->request.parser.content_length != ULLONG_MAX && bbs->request.parser.content_length > 0) {
				//bbs->sio_bbs = persistent_bbs;
				bbs->request.no_uwsgi = 1;
				// buffer following data
				bbs->request.sio_post = 1;
				bbs->quiet_death = 1;
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
		//bbsr->do_not_free = 1;
		bbs->quiet_death = 1;
                // we can now clear the current session
		bb_session_close(bbs);
		// and map it to the new one
		bbs = persistent_bbs;

		// append the request (other requests could came in the same time)
		// TODO fix it !
/*
		bbs->requests_head = bbsr;
		bbs->requests_tail = bbsr;
		bbsr->prev = NULL;
		bbsr->next = NULL;
*/
		// end of TODO

		// and map the connection
		bbs->connection = bbc;
		// append the session to the connection
		if (!bbc->sessions_head) {
                	bbc->sessions_head = bbs;
                	bbc->sessions_tail = bbs;
        	}
        	else {
                	bbs->conn_prev = bbc->sessions_tail;
                	bbc->sessions_tail = bbs;
                	bbs->conn_prev->next = bbs;
        	}
		// finally fix the request
		//bbsr->bbs = bbs;

ready:
		// ok we are ready
		if (bbs->request.parser.method == HTTP_GET) {
			if (bbs->sio_connected) {
				bbs->request.no_uwsgi = 1;
				struct bb_socketio_message *bbsm = bbs->sio_queue;
                		if (bbsm) {
					if (bbs->sio_poller) {
						ev_feed_event(blastbeat.loop, &bbs->timer.timer, EV_TIMER);
						bbs->sio_poller = 0;
						return 0;
					}
                			if (bb_socketio_send(bbs, bbsm->buf, bbsm->len)) {
                        			fprintf(stderr,"unable to deliver message\n");
                			}
                			bbs->sio_queue = bbsm->next;
                			free(bbsm);
					return 0;
				}
				ev_timer_stop(blastbeat.loop, &bbs->timer.timer);
				bbs->timer.session = bbs;
				ev_timer_set(&bbs->timer.timer, 5.0, 0.0);
				ev_timer_start(blastbeat.loop, &bbs->timer.timer);
				bbs->sio_poller = 1;
				return 0;
			}
			else {
				bbs->request.http_major = '0' + bbs->request.parser.http_major;
        			bbs->request.http_minor = '0' + bbs->request.parser.http_minor;

				if (bb_wq_push(bbs->connection, "HTTP/", 5, 0)) return -1;
                		if (bb_wq_push(bbs->connection, &bbs->request.http_major, 1, 0)) return -1;
                		if (bb_wq_push(bbs->connection, ".", 1, 0)) return -1;
                		if (bb_wq_push(bbs->connection, &bbs->request.http_minor, 1, 0)) return -1;

				const char *connected = " 200 OK\r\nConnection: close\r\nContent-Type: text/plain; charset=UTF-8\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Max-Age: 3600\r\nContent-Length: 3\r\n\r\n1::";
				if (bb_wq_push(bbs->connection, (char *)connected, strlen(connected), 0)) return -1;
				if (bb_wq_push_close(bbs->connection)) return -1;	
				bbs->sio_connected = 1;
				// start the sio_timer
				// the first ping is after 1 second
        			//ev_timer_start(blastbeat.loop, &bbs->timer.timer);
				// TODO here we generate a socket.io/uwsgi packet
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

        if (bb_wq_push(bbs->connection, "HTTP/", 5, 0)) return -1;
        if (bb_wq_push(bbs->connection, &bbs->request.http_major, 1, 0)) return -1;
        if (bb_wq_push(bbs->connection, ".", 1, 0)) return -1;
        if (bb_wq_push(bbs->connection, &bbs->request.http_minor, 1, 0)) return -1;


	if (bb_wq_push(bbs->connection, (char *)headers, strlen(headers), 0)) return -1;
	if (bb_wq_push(bbs->connection, (char *)cl, chunk_len, 1)) return -1;

	if (bb_wq_push(bbs->connection, (char *)buf, len, 1)) return -1;

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
		ev_feed_event(blastbeat.loop, &bbs->timer.timer, EV_TIMER);
		bbs->sio_poller = 0;
	}

	return 0;
}
