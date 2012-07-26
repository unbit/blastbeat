#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

extern http_parser_settings bb_http_response_parser_settings;
extern http_parser_settings bb_http_response_parser_settings2;

static void manage_ping(char *identity, size_t len) {
	struct bb_dealer *bbd = blastbeat.dealers;
	time_t now = time(NULL);
	while(bbd) {
		if (!bb_strcmp(identity, len, bbd->identity, bbd->len)) {
			bbd->last_seen = now;
		}
		bbd = bbd->next;
	}
}

void bb_zmq_receiver(struct ev_loop *loop, struct ev_io *w, int revents) {

        uint32_t zmq_events = 0;
        size_t opt_len = sizeof(uint32_t);

        for(;;) {
                int ret = zmq_getsockopt(blastbeat.router, ZMQ_EVENTS, &zmq_events, &opt_len);
                if (ret < 0) {
                        perror("zmq_getsockopt()");
                        break;
                }

                if (zmq_events & ZMQ_POLLIN) {
                        uint64_t more = 0;
                        size_t more_size = sizeof(more);
                        int headers = 0;
                        int i;
                        zmq_msg_t msg[4];
                        for(i=0;i<4;i++) {
                                zmq_msg_init(&msg[i]);
                                zmq_recv(blastbeat.router, &msg[i], ZMQ_NOBLOCK);
                                if (zmq_getsockopt(blastbeat.router, ZMQ_RCVMORE, &more, &more_size)) {
                                        perror("zmq_getsockopt()");
                                        break;
                                }
                                if (!more && i < 3) {
                                        break;
                                }
                        }

                        // invalid message
                        if (i != 4) goto next;

                        // manage "pong" messages
			if (!strncmp(zmq_msg_data(&msg[2]), "pong", zmq_msg_size(&msg[2]))) {
				manage_ping(zmq_msg_data(&msg[0]), zmq_msg_size(&msg[0]));
				goto next;
			}

                        // message with uuid ?
                        if (zmq_msg_size(&msg[1]) != BB_UUID_LEN) goto next;

                        // dead/invalid session ?
                        struct bb_session *bbs = bb_sht_get(zmq_msg_data(&msg[1]));
                        if (!bbs) goto next;

                        struct bb_session_request *bbsr = bbs->requests_tail;
                        // no request running ?
                        if (!bbsr) goto next;

			bbs->dealer->last_seen = time(NULL);

                        if (!strncmp(zmq_msg_data(&msg[2]), "body", zmq_msg_size(&msg[2]))) {
                                if (!bbs->connection->spdy) {
                                        if (bb_wq_push_copy(bbs,zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]), 1)) {
                                                bb_connection_close(bbs->connection);
                                                goto next;
                                        }
                                        bbsr->written_bytes += zmq_msg_size(&msg[2]);
                                        // if Content-Length is specified, check it...
                                        if (bbsr->content_length != ULLONG_MAX && bbsr->written_bytes >= bbsr->content_length && bbsr->close) {
                                                if (bb_wq_push_close(bbs->connection))
                                                        bb_connection_close(bbs->connection);
                                        }
                                }
                                else {
                                        if (bb_spdy_send_body(bbsr, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3])))
                                                bb_session_close(bbs);
                                }
                                goto next;
                        }

                        if (!strncmp(zmq_msg_data(&msg[2]), "websocket", zmq_msg_size(&msg[2]))) {
                                if (bb_websocket_reply(bbsr, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3])))
                                        bb_connection_close(bbs->connection);
                                goto next;
                        }

                        if (!strncmp(zmq_msg_data(&msg[2]), "chunk", zmq_msg_size(&msg[2]))) {
                                if (bb_manage_chunk(bbsr, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3])))
                                        bb_connection_close(bbs->connection);
                                goto next;
                        }


			if (!strncmp(zmq_msg_data(&msg[2]), "headers", zmq_msg_size(&msg[2]))) {
                                if (!bbs->connection->spdy) {
                                        http_parser parser;
                                        http_parser_init(&parser, HTTP_RESPONSE);
                                        parser.data = bbsr;
                                        int res = http_parser_execute(&parser, &bb_http_response_parser_settings, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]));
                                        // invalid headers ?
                                        if (res != zmq_msg_size(&msg[3])) {
                                                bb_connection_close(bbs->connection);
                                                goto next;
                                        }
                                        if (bb_wq_push_copy(bbs->connection, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]), 1))
                                                bb_connection_close(bbs->connection);
                                }
                                else {
                                        // in SPDY mode we parse headers as a normal HTTP request (saving data)
                                        http_parser_init(&bbsr->parser, HTTP_RESPONSE);
                                        bbsr->parser.data = bbsr;
                                        int res = http_parser_execute(&bbsr->parser, &bb_http_response_parser_settings2, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]));
                                        // invalid headers ?
                                        if (res != zmq_msg_size(&msg[3])) {
                                                bb_session_close(bbs);
                                                goto next;
                                        }
                                        if (bb_spdy_send_headers(bbsr))
                                                bb_session_close(bbs);
                                }
                                goto next;
                        }

                        if (!strncmp(zmq_msg_data(&msg[2]), "retry", zmq_msg_size(&msg[2]))) {
                                if (bbs->hops >= blastbeat.max_hops) {
                                        bb_session_close(bbs);
                                        goto next;
                                }
                                if (bb_set_dealer(bbs, bbs->vhost->name, bbs->vhost->len)) {
                                        bb_connection_close(bbs->connection);
                                        goto next;
                                }
                                bb_zmq_send_msg(bbs->dealer->identity, bbs->dealer->len, (char *) &bbs->uuid_part1, BB_UUID_LEN, "uwsgi", 5, bbsr->uwsgi_buf, bbsr->uwsgi_pos);
                                bbs->hops++;
                                goto next;
                        }

                        if (!strncmp(zmq_msg_data(&msg[2]), "end", zmq_msg_size(&msg[2]))) {
                                if (bb_wq_push_close(bbs)) {
                                        bb_connection_close(bbs->connection);
                                }
                                goto next;
                        }

next:
                        zmq_msg_close(&msg[0]);
                        zmq_msg_close(&msg[1]);
                        zmq_msg_close(&msg[2]);
                        zmq_msg_close(&msg[3]);

                        continue;
                }

                break;
        }
}

