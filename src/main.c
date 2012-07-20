#include "../blastbeat.h"

struct blastbeat_server blastbeat;

extern http_parser_settings bb_http_parser_settings;
extern http_parser_settings bb_http_response_parser_settings;

struct bb_session_request *bb_new_request(struct bb_session *bbs) {

	struct bb_session_request *bbsr = malloc(sizeof(struct bb_session_request));
	if (!bbsr) {
		perror("malloc()");
		return NULL;
	}
	memset(bbsr, 0, sizeof(struct bb_session_request));
	bbsr->bbs = bbs;
	http_parser_init(&bbsr->parser, HTTP_REQUEST);
        bbsr->parser.data = bbsr;
        bbsr->last_was_value = 1;

	if (!bbs->requests_head) {
		//printf("first request\n");
		bbs->requests_head = bbsr;
		bbs->requests_tail = bbsr;
	}
	else {
		bbs->requests_tail->next = bbsr;
		bbs->requests_tail = bbsr;
	}

	bbs->new_request = 0;	
	return bbsr;
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

void bb_session_close(struct bb_session *bbs) {
	int i;
	ev_io_stop(blastbeat.loop, &bbs->read_event);
	close(bbs->fd);
	blastbeat.fd_table[bbs->fd] = NULL;
	struct bb_session_request *bbsr = bbs->requests_head;
	while(bbsr) {
		for(i=0;i<=bbsr->header_pos;i++) {
			free(bbsr->headers[i].key);
			free(bbsr->headers[i].value);
		}
		if (bbsr->uwsgi_buf) {
			free(bbsr->uwsgi_buf);
		}
		if (bbsr->websocket_message_queue) {
			free(bbsr->websocket_message_queue);
		}
		struct bb_session_request *tmp_bbsr = bbsr;
		bbsr = bbsr->next;
		free(tmp_bbsr);
	}

	// if linked to a dealer, send a 'end' message
	if (bbs->dealer) {
		bb_zmq_send_msg(bbs->dealer->identity, bbs->dealer->len, (char *) &bbs->fd, 4, "end", 3, "", 0);
	}

	free(bbs);
}

void bb_error_exit(char *what) {
	perror(what);
	exit(1);
}

void bb_error(char *what) {
	perror(what);
}

int bb_nonblock(int fd) {
	int arg;

        arg = fcntl(fd, F_GETFL, NULL);
        if (arg < 0) {
                bb_error("fcntl()");
		return -1;
        }
        arg |= O_NONBLOCK;
        if (fcntl(fd, F_SETFL, arg) < 0) {
                bb_error("fcntl()");
                return -1;
        }

	return 0;
}

int bb_stricmp(char *str1, size_t str1len, char *str2, size_t str2len) {
	if (str1len != str2len) return -1;
	return strncasecmp(str1, str2, str1len);
}

struct bb_http_header *bb_http_req_header(struct bb_session_request *bbsr, char *key, size_t keylen) {
	off_t i;
	for(i=1;i<=bbsr->header_pos;i++) {
		if (!bb_stricmp(key, keylen, bbsr->headers[i].key, bbsr->headers[i].keylen)) {
			return &bbsr->headers[i];
		}
	}

	return NULL;
} 

struct bb_dealer *bb_get_dealer(char *name, size_t len) {
	struct bb_virtualhost *vhost = blastbeat.vhosts;
	while(vhost) {
		if (!bb_stricmp(name, len, vhost->name, vhost->len)) {
			return vhost->dealers;
		}
		vhost = vhost->next;
	}
	return NULL;
}

static void read_callback(struct ev_loop *loop, struct ev_io *w, int revents) {

	char buf[8192];
	ssize_t len;
	struct bb_session *bbs = blastbeat.fd_table[w->fd];
	// something is seriously wrong !!!
	if (!bbs) {
	}
	//printf("read event from %d\n", w->fd);
	len = read(w->fd, buf, 8192);
	if (len > 0) {
		// if no request is initialized, allocate it
		if (bbs->new_request) {
			//printf("allocating a new request\n");
			if (!bb_new_request(bbs)) goto clear;
		}
		if (bbs->requests_tail->type == 0) {
			int res = http_parser_execute(&bbs->requests_tail->parser, &bb_http_parser_settings, buf, len);
			if (res != len) goto clear;
		}
		else if (bbs->requests_tail->type == BLASTBEAT_TYPE_WEBSOCKET) {
			if (bb_manage_websocket(bbs->requests_tail, buf, len)) {
				goto clear;
			}
		}
		//printf("res = %d\n", res);	
		return;
	}
	
	if (len == 0) {
		goto clear;
	}
	perror("read()");
	
clear:
	//printf("done\n");
	bb_session_close(bbs);
}

static void accept_callback(struct ev_loop *loop, struct ev_io *w, int revents) {
	//printf("accept on fd %d\n", w->fd);
	struct sockaddr_in sin;
	socklen_t sin_len = sizeof(sin);
	int client = accept(w->fd, (struct sockaddr *)&sin, &sin_len);
	if (client < 0) {
		perror("accept()");
		return;
	}

	if (bb_nonblock(client)) {
		close(client);
		return;
	}

	struct bb_session *bbs = malloc(sizeof(struct bb_session));
	if (!bbs) {
		perror("malloc()");
		close(client);
		return;
	}
	memset(bbs, 0, sizeof(struct bb_session));
	blastbeat.fd_table[client] = bbs;
	bbs->fd = client;
	bbs->new_request = 1;
	ev_io_init(&bbs->read_event, read_callback, client, EV_READ);
	ev_io_start(loop, &bbs->read_event);
}

static void pinger_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {

	struct bb_pinger *pinger = (struct bb_pinger *) w;

	struct bb_dealer *bbd = pinger->vhost->dealers;
	// get events before starting a potentially long write session
	ev_feed_event(blastbeat.loop, &blastbeat.event_zmq, EV_READ);
	while(bbd) {
		bb_raw_zmq_send_msg(bbd->identity, bbd->len, "", 0, "ping", 4, "", 0);
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
			int fd = -1;
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
			if (i != 4) continue;

			if (zmq_msg_size(&msg[1]) == 4) {
				memcpy(&fd, zmq_msg_data(&msg[1]), 4);
			}
			if (fd < 0 || fd > blastbeat.max_fd) continue;
			// dead session ?
			struct bb_session *bbs = blastbeat.fd_table[fd];
			if (!bbs) continue;

			struct bb_session_request *bbsr = bbs->requests_tail;
			// no request running ?
			if (!bbsr) continue;

			if (!strncmp(zmq_msg_data(&msg[2]), "body", zmq_msg_size(&msg[2]))) {
				ssize_t rlen = write(fd, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]));
				if (rlen > 0) {
					bbsr->written_bytes += rlen;
				}
				else {
					bb_session_close(bbs);	
					continue;
				}
				if (bbsr->content_length > 0 && bbsr->written_bytes >= bbsr->content_length && bbsr->close) {
					bb_session_close(bbs);	
					continue;
				}
			}
			if (!strncmp(zmq_msg_data(&msg[2]), "websocket", zmq_msg_size(&msg[2]))) {
				bb_websocket_reply(bbsr, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]));
				continue;
			}
			if (!strncmp(zmq_msg_data(&msg[2]), "chunk", zmq_msg_size(&msg[2]))) {
				char chunk[MAX_CHUNK_STORAGE];
				int chunk_len = snprintf(chunk, MAX_CHUNK_STORAGE, "%X\r\n", (unsigned int) zmq_msg_size(&msg[3]));
				//printf("CHUNK: %s %d\n", chunk, (unsigned int) zmq_msg_size(&msg[3]));
				write(fd, chunk, chunk_len);
				write(fd, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]));
				write(fd, "\r\n", 2);
				if (zmq_msg_size(&msg[3]) == 0 && bbsr->close) {
					bb_session_close(bbs);	
				}
				continue;
			}
			if (!strncmp(zmq_msg_data(&msg[2]), "headers", zmq_msg_size(&msg[2]))) {
				http_parser parser;
				http_parser_init(&parser, HTTP_RESPONSE);
				parser.data = bbsr;
				//parser.flags |= F_CONNECTION_KEEP_ALIVE;
				int res = http_parser_execute(&parser, &bb_http_response_parser_settings, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]));
				if (res != zmq_msg_size(&msg[3])) {
					bb_session_close(bbs);	
					continue;
				}
				write(fd, zmq_msg_data(&msg[3]), zmq_msg_size(&msg[3]));
				continue;
			}
			else if (!strncmp(zmq_msg_data(&msg[2]), "end", zmq_msg_size(&msg[2]))) {
				bb_session_close(bbs);
				continue;
			}

			zmq_msg_close(&msg[0]);
			zmq_msg_close(&msg[1]);
			zmq_msg_close(&msg[2]);
			zmq_msg_close(&msg[3]);
		
			continue;
		}

		break;
	}
}


int main(int argc, char *argv[]) {

	if (argc < 2) {
		fprintf(stderr, "syntax: blastbeat <configfile>\n");
		exit(1);
	}

	// set default values
	blastbeat.ping_freq = 3.0;
	bb_ini_config(argv[1]);

	// validate config
	if (!blastbeat.addr) {
		fprintf(stderr, "config error: please specify a valid 'bind' directive\n");
		exit(1);
	}

	if (!blastbeat.port) {
		fprintf(stderr, "config error: please specify a valid 'bind' directive\n");
		exit(1);
	}

	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl)) {
		bb_error_exit("unable to get the maximum file descriptors number: getrlimit()");
	}

	blastbeat.fd_table = malloc(sizeof(struct bb_session *) * rl.rlim_cur);
	if (!blastbeat.fd_table) {
		bb_error_exit("unable to allocate file descriptors table: malloc()");
	}
	blastbeat.max_fd = rl.rlim_cur;

	// report config
	struct bb_virtualhost *vhost = blastbeat.vhosts;
	fprintf(stdout,"*** starting BlastBeat ***\n");
	while(vhost) {
		fprintf(stdout, "[%s]\n", vhost->name);
		struct bb_dealer *bbd = vhost->dealers;
		while(bbd) {
			fprintf(stdout, "%s\n", bbd->identity);
			bbd = bbd->next;
		}
		vhost = vhost->next;
	}

	blastbeat.loop = EV_DEFAULT;
	
	int server = socket(AF_INET, SOCK_STREAM, 0);
	if (server < 0) {
		bb_error_exit("socket()");
	}

	int on = 1;
	if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int))) {
		bb_error_exit("setsockopt()");
	}

	if (setsockopt(server, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(int))) {
		bb_error_exit("setsockopt()");
	}

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(blastbeat.addr);
	sin.sin_port = htons(blastbeat.port);

	if (bind(server, (struct sockaddr *) &sin, sizeof(sin))) {
		bb_error_exit("unable to bind to HTTP address: bind()");
	}
	
	if (listen(server, 100) < 0) {
		bb_error_exit("unable to put HTTP socket in listen mode: listen()");
	}
	
	if (bb_nonblock(server)) {
		fprintf(stderr,"unable to put HTTP socket in non-blocking mode\n");
		exit(1);
	}

	void *context = zmq_init (1);
	
	blastbeat.router = zmq_socket(context, ZMQ_ROUTER);

	if (zmq_bind(blastbeat.router, blastbeat.zmq)) {
		bb_error_exit("unable to bind to zmq socket: zmq_bind()");
	}

	size_t opt_len = sizeof(int);
	if (zmq_getsockopt(blastbeat.router, ZMQ_FD, &blastbeat.zmq_fd, &opt_len)) {
		bb_error_exit("unable to configure zmq socket: zmq_getsockopt()");
	}

	ev_io_init(&blastbeat.event_accept, accept_callback, server, EV_READ);	
	ev_io_start(blastbeat.loop, &blastbeat.event_accept);

	ev_io_init(&blastbeat.event_zmq, bb_zmq_receiver, blastbeat.zmq_fd, EV_READ);
	ev_io_start(blastbeat.loop, &blastbeat.event_zmq);

	vhost = blastbeat.vhosts;
	while(vhost) {
		vhost->pinger.vhost = vhost;
		ev_timer_init(&vhost->pinger.pinger, pinger_cb, blastbeat.ping_freq, blastbeat.ping_freq);
		ev_timer_start(blastbeat.loop, &vhost->pinger.pinger);
		vhost = vhost->next;
	}

	ev_loop(blastbeat.loop, 0);
	return 0;

}
