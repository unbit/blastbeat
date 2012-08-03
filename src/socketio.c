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


int bb_manage_socketio(struct bb_session_request *bbsr) {
	char *url = bbsr->headers[0].key;
	size_t url_len = bbsr->headers[0].keylen;

	char *query_string = memchr(url, '?', url_len);
	if (query_string) {
		url_len = query_string-url;
	}

	fprintf(stderr,"SOCKET.IO %.*s\n", url_len, url);

	// handshake
	if (url_len == 13) {
		char *supported = "xhr-polling";
		char handshake[36+3+3+1+11];
		uuid_t *session_uuid = (uuid_t *) &bbsr->bbs->uuid_part1; 
		uuid_unparse(*session_uuid, handshake);
		memcpy(handshake+36, ":60:60:", 7);
		memcpy(handshake+36+7, supported, 11);


		const char *hs_headers = " 200 OK\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\nContent-Length: 54\r\nAccess-Control-Allow-Origin: null\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Max-Age: 3600\r\n\r\n";

        	if (bb_wq_push(bbsr->bbs->connection, "HTTP/", 5, 0)) return -1;
        	if (bb_wq_push(bbsr->bbs->connection, &bbsr->http_major, 1, 0)) return -1;
        	if (bb_wq_push(bbsr->bbs->connection, ".", 1, 0)) return -1;
        	if (bb_wq_push(bbsr->bbs->connection, &bbsr->http_minor, 1, 0)) return -1;
        	if (bb_wq_push(bbsr->bbs->connection, (char *)hs_headers, strlen(hs_headers), 0)) return -1;
        	if (bb_wq_push_copy(bbsr->bbs->connection, handshake, 54, 1)) return -1;

		// mark the session as persistent
		bbsr->bbs->persistent = 1;

		fprintf(stderr,"HANDSHAKE DONE: %.*s\n", 54, handshake);
		bbsr->no_uwsgi = 1;

        	return 0;

	}
	//xhr-polling/a7b23852-2388-41d7-8f20-8cff5be70e82
	else if (url_len == 13 + 11 + 1 + 36) {


		fprintf(stderr,"CHECKING\n");
		uuid_t sio_uuid;
		char tmp_uuid[37];
		memcpy(tmp_uuid, url+13 + 11 + 1, 36);
		tmp_uuid[36] = 0;
		if (uuid_parse(tmp_uuid, sio_uuid)) return -1;
		fprintf(stderr,"CHECKING %s\n", tmp_uuid);
		fprintf(stderr,"needed check !!!\n");	
		struct bb_session *persistent_bbs = bb_sht_get((char *)sio_uuid);
		
		if (!persistent_bbs) return -1;
		// skip non-persistent connection
		if (!persistent_bbs->persistent) return -1;

		// TODO check for already running pollers...
		
		fprintf(stderr,"old session found !!!\n");

		// sending messages does not require remapping the session
		if (bbsr->parser.method == HTTP_POST) {
			fprintf(stderr,"POST\n");
				bbsr->http_major = '0' + bbsr->parser.http_major;
        			bbsr->http_minor = '0' + bbsr->parser.http_minor;

				if (bb_wq_push(bbsr->bbs->connection, "HTTP/", 5, 0)) return -1;
                		if (bb_wq_push(bbsr->bbs->connection, &bbsr->http_major, 1, 0)) return -1;
                		if (bb_wq_push(bbsr->bbs->connection, ".", 1, 0)) return -1;
                		if (bb_wq_push(bbsr->bbs->connection, &bbsr->http_minor, 1, 0)) return -1;

			const char *connected = " 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Max-Age: 3600\r\nContent-Length: 1\r\n\r\n1";
			if (bb_wq_push(bbsr->bbs->connection, (char *)connected, strlen(connected), 0)) return -1;
			if (bb_wq_push_close(bbsr->bbs->connection)) return -1;	
			if (bbsr->content_length != ULLONG_MAX && bbsr->content_length > 0) {
				bbsr->sio_bbs = persistent_bbs;
				bbsr->no_uwsgi = 1;
				// buffer following data
				bbsr->sio_post = 1;
				bbsr->bbs->quiet_death = 1;
				return 0;
			}
			return -1;	
		}


		struct bb_session *bbs = bbsr->bbs;

		// is it already the correct session ?
		if (!memcmp((char *)sio_uuid, (char *) &bbs->uuid_part1, 16)) goto ready;

		// ok, prepare for the heavy part:
		// get the current connection
		struct bb_connection *bbc = bbs->connection;
		// close the current session but without freeing the request
		bbsr->do_not_free = 1;
		bbs->quiet_death = 1;
                // we can now clear the current session
		bb_session_close(bbs);
		// and map it to the new one
		bbs = persistent_bbs;

		// append the request (other requests could came in the same time)
		// TODO fix it !
		bbs->requests_head = bbsr;
		bbs->requests_tail = bbsr;
		bbsr->prev = NULL;
		bbsr->next = NULL;
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
		bbsr->bbs = bbs;

ready:
		// ok we are ready
		if (bbsr->parser.method == HTTP_GET) {
			if (bbs->sio_connected) {
				bbs->sio_poller = 1;
				fprintf(stderr,"WAITING FOR MESSAGES\n");
				bbsr->no_uwsgi = 1;
				ev_timer_stop(blastbeat.loop, &bbs->timer.timer);
				ev_timer_set(&bbs->timer.timer, 5.0, 0.0);
				ev_timer_start(blastbeat.loop, &bbs->timer.timer);
				return 0;
			}
			else {
				fprintf(stderr, "CONNECTED\n");
				bbsr->http_major = '0' + bbsr->parser.http_major;
        			bbsr->http_minor = '0' + bbsr->parser.http_minor;

				if (bb_wq_push(bbsr->bbs->connection, "HTTP/", 5, 0)) return -1;
                		if (bb_wq_push(bbsr->bbs->connection, &bbsr->http_major, 1, 0)) return -1;
                		if (bb_wq_push(bbsr->bbs->connection, ".", 1, 0)) return -1;
                		if (bb_wq_push(bbsr->bbs->connection, &bbsr->http_minor, 1, 0)) return -1;

				const char *connected = " 200 OK\r\nConnection: close\r\nContent-Type: text/plain; charset=UTF-8\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Max-Age: 3600\r\nContent-Length: 3\r\n\r\n1::";
				if (bb_wq_push(bbsr->bbs->connection, (char *)connected, strlen(connected), 0)) return -1;
				if (bb_wq_push_close(bbsr->bbs->connection)) return -1;	
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

int bb_socketio_push(struct bb_session_request *bbsr, char type, char *buf, size_t len) {
	
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

	//is a poller attached to the session ?
	if (bbsr->bbs->sio_poller) {
		return 0;		
	}

	struct bb_session *bbs = bbsr->bbs;
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
	if (last_bbsm) {
		last_bbsm->next = bbsm;
	}
	else {
		bbs->sio_queue = bbsm;
	}

	return 0;
}
