#include "../blastbeat.h"

static int url_cb(http_parser *parser, const char *buf, size_t len) {
        struct bb_session_request *bbsr = (struct bb_session_request *) parser->data;
        if (!bbsr->headers[0].key) {
                bbsr->headers[0].key = malloc(len);
                memcpy(bbsr->headers[0].key, buf, len);
                bbsr->headers[0].keylen = len;
        }
        else {
                bbsr->headers[0].key = realloc(bbsr->headers[0].key, bbsr->headers[0].keylen + len);
                memcpy(bbsr->headers[0].key + bbsr->headers[0].keylen + len, buf, len);
                bbsr->headers[0].keylen += len;
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
        struct bb_session_request *bbsr = (struct bb_session_request *) parser->data;
        if (bbsr->last_was_value) {
                bbsr->header_pos++;
                bbsr->headers[bbsr->header_pos].key = malloc(len);
                memcpy(bbsr->headers[bbsr->header_pos].key, buf, len);
                bbsr->headers[bbsr->header_pos].keylen = len;
        }
        else {
                bbsr->headers[bbsr->header_pos].key = realloc(bbsr->headers[bbsr->header_pos].key, bbsr->headers[bbsr->header_pos].keylen + len);
                memcpy(bbsr->headers[bbsr->header_pos].key + bbsr->headers[bbsr->header_pos].keylen, buf, len);
                bbsr->headers[bbsr->header_pos].keylen += len;
        }
        bbsr->last_was_value = 0;
        return 0;
}

static int header_value_cb(http_parser *parser, const char *buf, size_t len) {
        struct bb_session_request *bbsr = (struct bb_session_request *) parser->data;
        if (!bbsr->last_was_value) {
                bbsr->headers[bbsr->header_pos].value = malloc(len);
                memcpy(bbsr->headers[bbsr->header_pos].value, buf, len);
                bbsr->headers[bbsr->header_pos].vallen = len;
        }
        else {
                bbsr->headers[bbsr->header_pos].value = realloc(bbsr->headers[bbsr->header_pos].value, bbsr->headers[bbsr->header_pos].vallen + len);
                memcpy(bbsr->headers[bbsr->header_pos].value + bbsr->headers[bbsr->header_pos].vallen, buf, len);
                bbsr->headers[bbsr->header_pos].vallen += len;
        }
        bbsr->last_was_value = 1;
        return 0;
}

static int body_cb(http_parser *parser, const char *buf, size_t len) {
        struct bb_session_request *bbsr = (struct bb_session_request *) parser->data;
        // send a message as "body"
	bb_zmq_send_msg(bbsr->bbs->dealer->identity, bbsr->bbs->dealer->len, (char *) &bbsr->bbs->fd, 4, "body", 4, buf, len);
        return 0;
}

static int response_headers_complete(http_parser *parser) {
        struct bb_session_request *bbsr = (struct bb_session_request *) parser->data;
        if (!http_should_keep_alive(parser)) {
                bbsr->close = 1;
        }
        if (parser->content_length != ULLONG_MAX) {
                bbsr->content_length = parser->content_length;
        }
        return 0;
}

static int bb_session_headers_complete(http_parser *parser) {
        //printf("headers parsed\n");
        struct bb_session_request *bbsr = (struct bb_session_request *) parser->data;
        off_t i;
        //printf("%s %.*s HTTP/%d.%d\n", http_method_str(parser->method), (int) bbsr->headers[0].keylen, bbsr->headers[0].key, parser->http_major, parser->http_minor);
        /*
        for(i=1;i<=bbsr->header_pos;i++) {
                printf("%.*s: %.*s\n", (int) bbsr->headers[i].keylen, bbsr->headers[i].key, (int)bbsr->headers[i].vallen, bbsr->headers[i].value);
        }
        */

        // ok get the Host header
        struct bb_http_header *bbhh = bb_http_req_header(bbsr, "Host", 4);
        if (!bbhh) {
                return -1;
        }

        if (!bbsr->bbs->dealer) {
                bbsr->bbs->dealer = bb_get_dealer(bbhh->value, bbhh->vallen);
        	if (!bbsr->bbs->dealer) {
                	return -1;
        	}
        }

        if (parser->upgrade) {
                struct bb_http_header *bbhh = bb_http_req_header(bbsr, "Upgrade", 7);
                if (bbhh) {
                        if (!bb_stricmp("websocket", 9, bbhh->value, bbhh->vallen)) {
                                bbsr->type = BLASTBEAT_TYPE_WEBSOCKET;
                                bb_send_websocket_handshake(bbsr);
                                return 0;
                        }
                }
        }

        if (!http_should_keep_alive(parser)) {
                //printf("NO KEEP ALIVE !!!\n");
                bbsr->close = 1;
        }

        // now encode headers in a uwsgi packet and send it as "headers" message
	if (bb_uwsgi(bbsr)) {
		return -1;
	}
        bb_zmq_send_msg(bbsr->bbs->dealer->identity, bbsr->bbs->dealer->len, (char *) &bbsr->bbs->fd, 4, "uwsgi", 5, bbsr->uwsgi_buf, bbsr->uwsgi_pos);
        return 0;
}

static int bb_session_request_complete(http_parser *parser) {
        if (parser->upgrade) return 0;
        if (http_should_keep_alive(parser)) {
                // prepare for a new request
                struct bb_session_request *bbsr = (struct bb_session_request *) parser->data;
                bbsr->bbs->new_request = 1;
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
        .on_header_field = null_b_cb,
        .on_header_value = null_b_cb,
        .on_url = null_b_cb,
        .on_body = null_b_cb,
};


