#include "../blastbeat.h"

http_parser_settings bb_http_parser_settings;

int bb_http_func(struct bb_connection *bbc, char *buf, size_t len) {
	// in HTTP connections, only one session is allowed
	if (!bbc->sessions_head) {
		bbc->sessions_head = bb_session_new(bbc);
	}
	struct bb_session *bbs = bbc->sessions_head;
	if (!bbs) return -1;

	if (!bbs->request.initialized)
		bb_initialize_request(bbs);

	int res = http_parser_execute(&bbs->request.parser, &bb_http_parser_settings, buf, len);
	if (res != len) return -1;
	return 0;
}

int bb_http_send_headers(struct bb_session *bbs, char *buf, size_t len) {
	return bb_wq_push_copy(bbs, buf, len, BB_WQ_FREE);
}

int bb_http_send_end(struct bb_session *bbs) {
	return bb_wq_push_close(bbs);
}

int bb_http_send_body(struct bb_session *bbs, char *buf, size_t len) {
	if (bb_wq_push_copy(bbs, buf, len, BB_WQ_FREE))
		return -1;
	bbs->response.written_bytes += len;
	if (bbs->response.content_length != ULLONG_MAX &&
		bbs->response.written_bytes >= bbs->response.content_length &&
		bbs->response.close)
        	return bb_wq_push_close(bbs);
	return 0;
}

ssize_t bb_http_read(struct bb_connection *bbc, char *buf, size_t len) {
        return read(bbc->fd, buf, len);
}

ssize_t bb_http_write(struct bb_connection *bbc, char *buf, size_t len) {
        return write(bbc->fd, buf, len);
}


struct bb_http_header *bb_http_req_header(struct bb_session *bbs, char *key, size_t keylen) {
        off_t i;
        for(i=1;i<=bbs->request.header_pos;i++) {
                if (!bb_stricmp(key, keylen, bbs->request.headers[i].key, bbs->request.headers[i].keylen)) {
                        return &bbs->request.headers[i];
                }
        }

        return NULL;
}


int bb_manage_chunk(struct bb_session *bbs, char *buf, size_t len) {
	char *chunk = malloc(MAX_CHUNK_STORAGE);
        if (!chunk) {
        	bb_error("unable to allocate memory for chunked response: malloc()");
                bb_session_close(bbs);
		return -1;
        }
        int chunk_len = snprintf(chunk, MAX_CHUNK_STORAGE, "%X\r\n", (unsigned int) len);

        if (bb_wq_push(bbs, chunk, chunk_len, BB_WQ_FREE)) goto end;
        if (bb_wq_push_copy(bbs, buf, len, BB_WQ_FREE)) goto end;
        if (bb_wq_push(bbs, "\r\n", 2, 0)) goto end;
        if (len == 0 && bbs->response.close) {
        	if (bb_wq_push_close(bbs)) goto end;
	}
	return 0;
end:
	bb_session_close(bbs);
	return -1;
}

static int url_cb(http_parser *parser, const char *buf, size_t len) {
        struct bb_session *bbs = (struct bb_session *) parser->data;
        if (!bbs->request.headers[0].key) {
                bbs->request.headers[0].key = malloc(len);
                memcpy(bbs->request.headers[0].key, buf, len);
                bbs->request.headers[0].keylen = len;
        }
        else {
                bbs->request.headers[0].key = realloc(bbs->request.headers[0].key, bbs->request.headers[0].keylen + len);
                memcpy(bbs->request.headers[0].key + bbs->request.headers[0].keylen + len, buf, len);
                bbs->request.headers[0].keylen += len;
        }
        return 0;
}


static int null_cb(http_parser *parser) {
        return 0;
}

static int null_b_cb(http_parser *parser, const char *buf, size_t len) {
        return 0;
}

static int header_field_cb(http_parser *parser, const char *buf, size_t len) {
        struct bb_session *bbs = (struct bb_session *) parser->data;
        if (bbs->request.last_was_value) {
                bbs->request.header_pos++;
                bbs->request.headers[bbs->request.header_pos].key = malloc(len);
                memcpy(bbs->request.headers[bbs->request.header_pos].key, buf, len);
                bbs->request.headers[bbs->request.header_pos].keylen = len;
        }
        else {
                bbs->request.headers[bbs->request.header_pos].key = realloc(bbs->request.headers[bbs->request.header_pos].key, bbs->request.headers[bbs->request.header_pos].keylen + len);
                memcpy(bbs->request.headers[bbs->request.header_pos].key + bbs->request.headers[bbs->request.header_pos].keylen, buf, len);
                bbs->request.headers[bbs->request.header_pos].keylen += len;
        }
        bbs->request.last_was_value = 0;
        return 0;
}

static int header_value_cb(http_parser *parser, const char *buf, size_t len) {
        struct bb_session *bbs = (struct bb_session *) parser->data;
        if (!bbs->request.last_was_value) {
                bbs->request.headers[bbs->request.header_pos].value = malloc(len);
                memcpy(bbs->request.headers[bbs->request.header_pos].value, buf, len);
                bbs->request.headers[bbs->request.header_pos].vallen = len;
        }
        else {
                bbs->request.headers[bbs->request.header_pos].value = realloc(bbs->request.headers[bbs->request.header_pos].value, bbs->request.headers[bbs->request.header_pos].vallen + len);
                memcpy(bbs->request.headers[bbs->request.header_pos].value + bbs->request.headers[bbs->request.header_pos].vallen, buf, len);
                bbs->request.headers[bbs->request.header_pos].vallen += len;
        }
        bbs->request.last_was_value = 1;
        return 0;
}

static int header_ptr_field_cb(http_parser *parser, const char *buf, size_t len) {
        struct bb_session *bbs = (struct bb_session *) parser->data;
        if (bbs->response.last_was_value) {
                bbs->response.header_pos++;
                bbs->response.headers[bbs->response.header_pos].key = (char *) buf;
                bbs->response.headers[bbs->response.header_pos].keylen = len;
        }
        else {
                bbs->response.headers[bbs->response.header_pos].keylen += len;
        }
        bbs->response.last_was_value = 0;
        return 0;
}

static int header_ptr_value_cb(http_parser *parser, const char *buf, size_t len) {
        struct bb_session *bbs = (struct bb_session *) parser->data;
        if (!bbs->response.last_was_value) {
                bbs->response.headers[bbs->response.header_pos].value = (char *) buf;
                bbs->response.headers[bbs->response.header_pos].vallen = len;
        }
        else {
                bbs->response.headers[bbs->response.header_pos].vallen += len;
        }
        bbs->response.last_was_value = 1;
        return 0;
}


static int body_cb(http_parser *parser, const char *buf, size_t len) {
        struct bb_session *bbs = (struct bb_session *) parser->data;
        // send a message as "body"
	if (bbs->request.sio_post) {
		char *new_buf = realloc(bbs->request.sio_post_buf, bbs->request.sio_post_buf_size+len);
		if (!new_buf) {
			bb_error("realloc()");
			return -1;
		}
		bbs->request.sio_post_buf = new_buf;
		memcpy(bbs->request.sio_post_buf+bbs->request.sio_post_buf_size, buf, len);
		bbs->request.sio_post_buf_size+=len;
	}
	else {
		bb_zmq_send_msg(bbs->dealer->identity, bbs->dealer->len, (char *) &bbs->uuid_part1, BB_UUID_LEN, "body", 4, (char *) buf, len);
	}
        return 0;
}

static int response_headers_complete(http_parser *parser) {
        struct bb_session *bbs = (struct bb_session *) parser->data;
	if (parser->content_length != ULLONG_MAX) {
                bbs->response.content_length = parser->content_length;
        }
        if (!http_should_keep_alive(parser)) {
                bbs->response.close = 1;
        }
        return 0;
}

static int bb_session_headers_complete(http_parser *parser) {
        struct bb_session *bbs = (struct bb_session *) parser->data;

        // ok get the Host header
        struct bb_http_header *bbhh = bb_http_req_header(bbs, "Host", 4);
        if (!bbhh) {
                return -1;
        }

        if (!bbs->dealer) {
                if (bb_set_dealer(bbs, bbhh->value, bbhh->vallen)) {
                	return -1;
        	}
        }

	// check for mountpoint...
	// check for socket.io
	if (!bb_startswith(bbs->request.headers[0].key, bbs->request.headers[0].keylen, "/socket.io/1/", 13)) {
		if (bb_manage_socketio(bbs)) {
			return -1;
		}
	}

        if (parser->upgrade) {
                struct bb_http_header *bbhh = bb_http_req_header(bbs, "Upgrade", 7);
                if (bbhh) {
                        if (!bb_stricmp("websocket", 9, bbhh->value, bbhh->vallen)) {
				bbs->connection->func = bb_websocket_func;
                                bb_send_websocket_handshake(bbs);
				goto msg;
                        }
                }
        }


        if (!http_should_keep_alive(parser)) {
                //printf("NO KEEP ALIVE !!!\n");
                bbs->response.close = 1;
        }

msg:
	if (bbs->request.no_uwsgi) return 0;
        // now encode headers in a uwsgi packet and send it as "headers" message
	if (bb_uwsgi(bbs)) {
		return -1;
	}
        bb_zmq_send_msg(bbs->dealer->identity, bbs->dealer->len, (char *) &bbs->uuid_part1, BB_UUID_LEN, "uwsgi", 5, bbs->request.uwsgi_buf, bbs->request.uwsgi_pos);
        return 0;
}

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

static size_t str2num(char *str, int len) {

        int i;
        size_t num = 0;

        size_t delta = pow(10, len);

        for (i = 0; i < len; i++) {
                delta = delta / 10;
                num += delta * (str[i] - 48);
        }

        return num;
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

static int bb_session_request_complete(http_parser *parser) {
        if (parser->upgrade) return 0;
	struct bb_session *bbs = (struct bb_session *) parser->data;
	if (bbs->request.sio_post) {
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
				size_t part_len = str2num(base_of_num, end_of_num);
				if (*ptr++ != '\xef') return -1;	
				if (ptr+1 > watermark) return -1;
				if (*ptr++ != '\xbf') return -1;	
				if (ptr+1 > watermark) return -1;
				if (*ptr++ != '\xbd') return -1;	
				if (ptr+1 > watermark) return -1;
				if (ptr+part_len > watermark) return -1;
/*
				if (bb_socketio_message(bbsr->sio_bbs, ptr, part_len))
					return -1;
*/
				ptr+=part_len;
			}
		}
		else {
/*
			if (bb_socketio_message(bbsr->sio_bbs, bbsr->sio_post_buf, bbsr->sio_post_buf_size))
				return -1;
*/
		}
	} 
        if (http_should_keep_alive(parser)) {
                // prepare for a new request
		// TODO clear the current request
        }
        return 0;
}


http_parser_settings bb_http_parser_settings = {
        .on_message_begin = null_cb,
        .on_message_complete = bb_session_request_complete,
        .on_headers_complete = bb_session_headers_complete,
        .on_header_field = header_field_cb,
        .on_header_value = header_value_cb,
        .on_url = url_cb,
        .on_body = body_cb,
};

http_parser_settings bb_http_response_parser_settings = {
        .on_message_begin = null_cb,
        .on_message_complete = null_cb,
        .on_headers_complete = response_headers_complete,
        .on_header_field = header_ptr_field_cb,
        .on_header_value = header_ptr_value_cb,
        .on_url = null_b_cb,
        .on_body = null_b_cb,
};
