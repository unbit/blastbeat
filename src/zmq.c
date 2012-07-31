#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

/* message format (from dealers)


SID (used for authroization and for getting the sender session)
TYPE (used for message type and routing)
BODY (body of message)

routing:

'type' -> standard blastbeat->peer peer->blastbeat
'group:type' -> message router to a group
'@sid:type' -> message routed to a specific session

*/

#define on_cmd(x) if (!strncmp(command, x, command_len))

#define foreach_session_in_group	if (route[0] == '@') {\
					in_group = 0;\
					struct bb_group *bbg = bb_ght_get(bbs->vhost, route, route_len);\
                                        if (!bbg) goto next;\
                                        struct bb_group_session *bbgs = bbg->sessions;\
                                        while(bbgs) {\
                                                if (bbgs->session != bbs) {
#define	end_foreach				}\
						else {\
							in_group = 1;\
						}\
                                                bbgs = bbgs->next;\
                                        }\
					if (!in_group) goto next;\
					}


extern http_parser_settings bb_http_response_parser_settings;
extern http_parser_settings bb_http_response_parser_settings2;

static char *bb_get_route(char *buf, size_t len, size_t *rlen) {
	while(len>0) {
		if (buf[len--] == ':') {
			*rlen = len+1;
			return buf;
		}
	}

	return NULL;
}

void bb_raw_zmq_send_msg(char *identity, size_t identity_len, char *sid, size_t sid_len, char *t, size_t t_len, char *body, size_t body_len) {

        zmq_msg_t z_i,z_sid,z_t, z_body;

        zmq_msg_init_size(&z_i, identity_len);
        zmq_msg_init_size(&z_sid, sid_len);
        zmq_msg_init_size(&z_t, t_len);
        zmq_msg_init_size(&z_body, body_len);

        memcpy(zmq_msg_data(&z_i), identity, identity_len);
        memcpy(zmq_msg_data(&z_sid), sid, sid_len);
        memcpy(zmq_msg_data(&z_t), t, t_len);
        memcpy(zmq_msg_data(&z_body), body, body_len);


        zmq_send(blastbeat.router, &z_i, ZMQ_SNDMORE);
        zmq_send(blastbeat.router, &z_sid, ZMQ_SNDMORE);
        zmq_send(blastbeat.router, &z_t, ZMQ_SNDMORE);
        for(;;) {
                int ret = zmq_send(blastbeat.router, &z_body, ZMQ_NOBLOCK);
                if (!ret) break;
                if (errno == EAGAIN) continue;
                bb_error("zmq_send()");
                break;
        }

        zmq_msg_close(&z_i);
        zmq_msg_close(&z_sid);
        zmq_msg_close(&z_t);
        zmq_msg_close(&z_body);

}

void bb_zmq_send_msg(char *identity, size_t identity_len, char *sid, size_t sid_len, char *t, size_t t_len, char *body, size_t body_len) {

        ev_feed_event(blastbeat.loop, &blastbeat.event_zmq, EV_READ);
        bb_raw_zmq_send_msg(identity, identity_len, sid, sid_len, t, t_len, body, body_len);
}



static void update_dealer(struct bb_dealer *bbd, time_t now) {
	bbd->last_seen = now;
	if (bbd->status == BLASTBEAT_DEALER_OFF) {
		bbd->status = BLASTBEAT_DEALER_AVAILABLE;
		fprintf(stderr, "node \"%s\" is available\n", bbd->identity);
	}	
}

static void manage_ping(char *identity, size_t len) {
	struct bb_dealer *bbd = blastbeat.dealers;
	time_t now = time(NULL);
	while(bbd) {
		if (!bb_strcmp(identity, len, bbd->identity, bbd->len)) {
			update_dealer(bbd, now);
			return;
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

			update_dealer(bbs->dealer, time(NULL));

			char *command = zmq_msg_data(&msg[2]);
			size_t command_len = zmq_msg_size(&msg[2]);

			size_t route_len = 0;
			char *route = bb_get_route(command, command_len, &route_len);
			if (route) {
				command = route + route_len + 1;
				command_len-=(route_len+1);
			}

			int in_group = 1;

			on_cmd("body") {
                                if (!bbs->connection->spdy) {
                                        if (bb_wq_push_copy(bbs->connection,zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]), 1)) {
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

			on_cmd("websocket") {
				if (route) {
					foreach_session_in_group
						if (bbgs->session->requests_tail) {
                                			if (bb_websocket_reply(bbgs->session->requests_tail, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3])))
                                        			bb_connection_close(bbgs->session->connection);
						}
                                        end_foreach
				}
                                if (bb_websocket_reply(bbsr, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3])))
                                       	bb_connection_close(bbs->connection);
                                goto next;
                        }

			on_cmd("chunk") {
				if (route) {
					foreach_session_in_group
						if (bbgs->session->requests_tail) {
                                			if (bb_manage_chunk(bbgs->session->requests_tail, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3])))
                                        			bb_connection_close(bbs->connection);
						}
					end_foreach
                                }
                                if (bb_manage_chunk(bbsr, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3])))
                                        bb_connection_close(bbs->connection);
                                goto next;
                        }


			on_cmd("headers") {
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

			on_cmd("retry") {
                                if (bbs->hops >= blastbeat.max_hops) {
                                        bb_connection_close(bbs->connection);
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

			on_cmd("msg") {
				if (!route) goto next;
				// check if it is a direct message
				if (route[0] == '@') {
					if (route_len == BB_UUID_LEN+1) {
						// cannot send messages to myself
						if (!memcmp(route+1, (char *) &bbs->uuid_part1, BB_UUID_LEN)) goto next;
						struct bb_session *bbs_dest = bb_sht_get(route+1);
						if (!bbs_dest) goto next;
						if (!bbs_dest->dealer) goto next;
						bb_zmq_send_msg(bbs_dest->dealer->identity, bbs_dest->dealer->len, route+1, BB_UUID_LEN, "msg", 3, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]));
					}
				}
				else {
					struct bb_group *bbg = bb_ght_get(bbs->vhost, route, route_len);
					if (!bbg) goto next;
					struct bb_group_session *bbgs = bbg->sessions;
					while(bbgs) {
						// do not route messages to myself
						if (bbgs->session != bbs) {
							if (bbgs->session->dealer) {
								bb_zmq_send_msg(bbgs->session->dealer->identity, bbgs->session->dealer->len,
									(char *) &bbgs->session->uuid_part1, BB_UUID_LEN, "msg", 3, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]));
							}
						}
						bbgs = bbgs->next;	
					}
				}
				goto next;
			}

			on_cmd("join") {
                                if (bb_join_group(bbs, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3])))
                                	bb_session_close(bbs);
                                goto next;
                        }

			on_cmd("end") {
				if (!bbs->connection->spdy) {
                                	if (bb_wq_push_close(bbs->connection)) {
                                        	bb_connection_close(bbs->connection);
                                	}
				}
				else {
                                        if (bb_spdy_send_body(bbsr, "", 0))
                                                bb_session_close(bbs);
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

