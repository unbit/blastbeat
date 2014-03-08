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

#define on_cmd(x, y) if (!bb_strcmp(command, command_len, x, y))

#define foreach_session_in_group	if (route[0] != '@') {\
					in_group = 0;\
					struct bb_group *bbg = bb_ght_get(bbs->vhost, route, route_len);\
                                        if (!bbg) goto next;\
                                        struct bb_group_session *bbgs = bbg->sessions;\
                                        while(bbgs) {\
                                                if (bbgs->session != bbs) {
#define	end_foreach				}\
						else if (!bbgs->noecho) {\
							in_group = 1;\
						}\
                                                bbgs = bbgs->next;\
                                        }\
					if (!in_group) goto next;\
					}


extern http_parser_settings bb_http_response_parser_settings;

static char *bb_get_route(char *buf, size_t len, size_t *rlen) {
	while(len>0) {
		if (buf[--len] == ':') {
			*rlen = len+1;
			return buf;
		}
	}

	return NULL;
}

void bb_raw_zmq_send_msg(struct bb_dealer *bbd, struct bb_session *bbs, char *sid, size_t sid_len, char *t, size_t t_len, char *body, size_t body_len) {

	if (bbs && bb_check_for_pipe(bbs, t, t_len, body, body_len)) return;

	// check for secure channels
	if (bbd->secure_key) {
	}

        zmq_msg_t z_i,z_sid,z_t, z_body;

        zmq_msg_init_size(&z_i, bbd->len);
        zmq_msg_init_size(&z_sid, sid_len);
        zmq_msg_init_size(&z_t, t_len);
        zmq_msg_init_size(&z_body, body_len);

        memcpy(zmq_msg_data(&z_i), bbd->identity, bbd->len);
        memcpy(zmq_msg_data(&z_sid), sid, sid_len);
        memcpy(zmq_msg_data(&z_t), t, t_len);
        memcpy(zmq_msg_data(&z_body), body, body_len);


        zmq_msg_send(&z_i, bbd->router->router, ZMQ_SNDMORE);
        zmq_msg_send(&z_sid, bbd->router->router, ZMQ_SNDMORE);
        zmq_msg_send(&z_t, bbd->router->router, ZMQ_SNDMORE);

	// router/dealers should never block...
        if (zmq_msg_send(&z_body, bbd->router->router, ZMQ_NOBLOCK)) {
                bb_error("zmq_send()");
        }

        zmq_msg_close(&z_i);
        zmq_msg_close(&z_sid);
        zmq_msg_close(&z_t);
        zmq_msg_close(&z_body);

}

void bb_zmq_send_msg(struct bb_dealer *bbd, struct bb_session *bbs, char *sid, size_t sid_len, char *t, size_t t_len, char *body, size_t body_len) {

        ev_feed_event(blastbeat.loop, &bbd->router->zmq_io.event, EV_READ);
        bb_raw_zmq_send_msg(bbd, bbs, sid, sid_len, t, t_len, body, body_len);
}



static void update_dealer(struct bb_dealer *bbd, ev_tstamp now) {
	bbd->last_seen = bb_now;
	if (bbd->status == BLASTBEAT_DEALER_OFF) {
		bbd->status = BLASTBEAT_DEALER_AVAILABLE;
		fprintf(stderr, "node \"%s\" is available\n", bbd->identity);
	}
}

static void manage_ping(struct bb_router *bbr, char *identity, size_t len) {
	struct bb_dealer *bbd = blastbeat.dealers;
	ev_tstamp now = bb_now;
	while(bbd) {
		// check for router and identity
		if (bbd->router == bbr && !bb_strcmp(identity, len, bbd->identity, bbd->len)) {
			update_dealer(bbd, now);
			return;
		}
		bbd = bbd->next;
	}
}

static void bb_zmq_manage_messages(struct bb_router *bbr) {

                        uint64_t more = 0;
                        size_t more_size = sizeof(more);
                        int i;
                        zmq_msg_t msg[4];
			zmq_msg_init(&msg[0]);
			zmq_msg_init(&msg[1]);
			zmq_msg_init(&msg[2]);
			zmq_msg_init(&msg[3]);

                        for(i=0;i<4;i++) {
                                zmq_msg_recv(&msg[i], bbr->router, ZMQ_NOBLOCK);
                                if (zmq_getsockopt(bbr->router, ZMQ_RCVMORE, &more, &more_size)) {
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
			if (!bb_strcmp(zmq_msg_data(&msg[2]), zmq_msg_size(&msg[2]), "pong", 4)) {
				manage_ping(bbr, zmq_msg_data(&msg[0]), zmq_msg_size(&msg[0]));
				goto next;
			}

                        // message with uuid ?
                        if (zmq_msg_size(&msg[1]) != BB_UUID_LEN) goto next;

                        // dead/invalid session/dealer ?
                        struct bb_session *bbs = bb_sht_get(zmq_msg_data(&msg[1]));
                        if (!bbs) goto next;
			if (!bbs->dealer) goto next;
			// check router/dealer pairing
			if (bbs->dealer->router != bbr) goto next;
			// check identity
			if (bb_strcmp(zmq_msg_data(&msg[0]), zmq_msg_size(&msg[0]), bbs->dealer->identity, bbs->dealer->len)) goto next;

			// update dealer activity
			ev_tstamp now = bb_now;
			bbs->last_seen = now;
			update_dealer(bbs->dealer, now);

			char *command = zmq_msg_data(&msg[2]);
			size_t command_len = zmq_msg_size(&msg[2]);

			size_t route_len = 0;
			char *route = bb_get_route(command, command_len, &route_len);
			if (route) {
				command = route + route_len + 1;
				command_len-=(route_len+1);
			}

			int in_group = 1;
			size_t msg_len = zmq_msg_size(&msg[3]);

			on_cmd("body", 4) {
				if (bbs->send_body(bbs, zmq_msg_data(&msg[3]), msg_len))
					bb_connection_close(bbs->connection);
				goto next;
                        }

			on_cmd("websocket", 9) {
				if (route) {
					foreach_session_in_group
                                		if (bb_websocket_reply(bbgs->session, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3])))
                                        		bb_connection_close(bbs->connection);
                                        end_foreach
				}
                                if (bb_websocket_reply(bbs, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3])))
                                       	bb_connection_close(bbs->connection);
                                goto next;
                        }

			on_cmd("chunk", 5) {
				if (route) {
					foreach_session_in_group
                                		if (bb_manage_chunk(bbgs->session, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3])))
                                        		bb_connection_close(bbs->connection);
					end_foreach
                                }
                                if (bb_manage_chunk(bbs, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3])))
                                        bb_connection_close(bbs->connection);
                                goto next;
                        }


			on_cmd("headers", 7) {
				bb_initialize_response(bbs);
				int res = http_parser_execute(&bbs->response.parser, &bb_http_response_parser_settings, zmq_msg_data(&msg[3]), msg_len);
				if (res != msg_len) {
					bb_connection_close(bbs->connection);
					goto next;
				}
				if (bbs->send_headers(bbs, zmq_msg_data(&msg[3]), msg_len))
					bb_connection_close(bbs->connection);
				goto next;
                        }

			on_cmd("push", 4) {
				// only connected sessions can push
				if (!bbs->connection) goto next;
				bb_initialize_response(bbs);
                                int res = http_parser_execute(&bbs->response.parser, &bb_http_response_parser_settings, zmq_msg_data(&msg[3]), msg_len);
                                if (res != msg_len) {
                                        bb_connection_close(bbs->connection);
                                        goto next;
                                }
                                if (bb_spdy_push_headers(bbs))
                                	bb_connection_close(bbs->connection);
				goto next;
			}

			on_cmd("retry", 5) {
                                if (bbs->hops >= blastbeat.max_hops) {
                                        bb_connection_close(bbs->connection);
                                        goto next;
                                }
                                if (bb_set_dealer(bbs, bbs->vhost->name, bbs->vhost->len)) {
                                        bb_connection_close(bbs->connection);
                                        goto next;
                                }
                                bb_zmq_send_msg(bbs->dealer, bbs, (char *) &bbs->uuid_part1, BB_UUID_LEN, "uwsgi", 5, bbs->request.uwsgi_buf, bbs->request.uwsgi_pos);
                                bbs->hops++;
                                goto next;
                        }

			on_cmd("msg", 3) {
				if (!route) goto next;
				// check if it is a direct message
				if (route[0] == '@') {
					if (route_len == BB_UUID_LEN+1) {
						// cannot send messages to myself
						if (!memcmp(route+1, (char *) &bbs->uuid_part1, BB_UUID_LEN)) goto next;
						struct bb_session *bbs_dest = bb_sht_get(route+1);
						if (!bbs_dest) goto next;
						if (!bbs_dest->dealer) goto next;
						bb_zmq_send_msg(bbs_dest->dealer, bbs_dest, route+1, BB_UUID_LEN, "msg", 3, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]));
					}
				}
				else {
					foreach_session_in_group
						bb_zmq_send_msg(bbgs->session->dealer, bbgs->session,
							(char *) &bbgs->session->uuid_part1, BB_UUID_LEN, "msg", 3, zmq_msg_data(&msg[3]), msg_len);
                                        end_foreach
					bb_zmq_send_msg(bbs->dealer, bbs,
                                        	(char *) &bbs->uuid_part1, BB_UUID_LEN, "msg", 3, zmq_msg_data(&msg[3]), msg_len);
				}
				goto next;
			}

			on_cmd("join", 4) {
                                if (bb_join_group(bbs, zmq_msg_data(&msg[3]), msg_len))
                                	bb_session_close(bbs);
                                goto next;
                        }

			on_cmd("cache", 5) {
				bb_cache_store(bbs, zmq_msg_data(&msg[3]), msg_len, 0);
                                goto next;
                        }

			on_cmd("fragcache", 9) {
				bb_cache_store(bbs, zmq_msg_data(&msg[3]), msg_len, 1);
                                goto next;
                        }

			on_cmd("echo", 4) {
				if (msg_len == 0) {
					bbs->noecho = 0;
				}
				else {
					struct bb_group *bbg = bb_ght_get(bbs->vhost, zmq_msg_data(&msg[3]), msg_len);
                                        if (!bbg) goto next;
                                        struct bb_group_session *bbgs = bbg->sessions;
                                        while(bbgs) {
						if (bbgs->session == bbs) {
							bbgs->noecho = 0;
							break;
						}
						bbgs = bbgs->next;
					}
				}
				goto next;
			}

			on_cmd("noecho", 6) {
				if (msg_len == 0) {
					bbs->noecho = 1;
				}
				else {
					struct bb_group *bbg = bb_ght_get(bbs->vhost, zmq_msg_data(&msg[3]), msg_len);
                                        if (!bbg) goto next;
                                        struct bb_group_session *bbgs = bbg->sessions;
                                        while(bbgs) {
						if (bbgs->session == bbs) {
							bbgs->noecho = 1;
							break;
						}
						bbgs = bbgs->next;
					}
				}
				goto next;
			}

			on_cmd("end", 3) {
				bbs->persistent = 0;
				if (bbs->send_end(bbs))
					bb_connection_close(bbs->connection);
                                goto next;
                        }

			on_cmd("pipe", 4) {
				if (bb_pipe_add(bbs, zmq_msg_data(&msg[3]), msg_len))
					bb_connection_close(bbs->connection);
                                goto next;
                        }


			on_cmd("frag", 4) {
				struct bb_cache_item *bbci = bb_cache_get(bbs->vhost, zmq_msg_data(&msg[3]), msg_len, 1);
				if (!bbci) goto next;
                                if (bbs->send_body(bbs, bbci->body, bbci->body_len))
                                        bb_connection_close(bbs->connection);
                                goto next;
                        }


			on_cmd("socket.io/event", 15) {
				if (bb_socketio_push(bbs, '5', zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]))) {
					// destroy the whole session
					bbs->persistent = 0;
					bb_connection_close(bbs->connection);
				}
				goto next;
			}

			on_cmd("socket.io/msg", 13) {
                                if (bb_socketio_push(bbs, '3', zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]))) {
                                        // destroy the whole session
                                        bbs->persistent = 0;
                                        bb_connection_close(bbs->connection);
                                }
                                goto next;
                        }

			on_cmd("socket.io/json", 14) {
                                if (bb_socketio_push(bbs, '4', zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]))) {
                                        // destroy the whole session
                                        bbs->persistent = 0;
                                        bb_connection_close(bbs->connection);
                                }
                                goto next;
                        }

			on_cmd("socket.io/end", 13) {
                                bb_socketio_push(bbs, '0', "", 0);
                                // destroy the whole session
                                bbs->persistent = 0;
                                bb_connection_close(bbs->connection);
                                goto next;
                        }


next:
                        zmq_msg_close(&msg[0]);
                        zmq_msg_close(&msg[1]);
                        zmq_msg_close(&msg[2]);
                        zmq_msg_close(&msg[3]);
}




void bb_zmq_receiver(struct ev_loop *loop, struct ev_io *w, int revents) {

	struct bb_router_io *bbr_io = (struct bb_router_io *) w;

        uint32_t zmq_events = 0;
        size_t opt_len = sizeof(uint32_t);

	ev_prepare_stop(blastbeat.loop, &bbr_io->router->zmq_check.prepare);

        int ret = zmq_getsockopt(bbr_io->router->router, ZMQ_EVENTS, &zmq_events, &opt_len);
        if (ret < 0) {
        	perror("zmq_getsockopt()");
		return;
        }

        if (zmq_events & ZMQ_POLLIN) {
		bb_zmq_manage_messages(bbr_io->router);
		ev_prepare_start(blastbeat.loop, &bbr_io->router->zmq_check.prepare);
	}
}

void bb_zmq_check_cb(struct ev_loop *loop, struct ev_prepare *w, int revents) {
	struct bb_router_prepare *bbr_prepare = (struct bb_router_prepare *) w;
	ev_feed_event(blastbeat.loop, &bbr_prepare->router->zmq_io.event, EV_READ);
}
