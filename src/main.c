#include "../blastbeat.h"

struct blastbeat_server blastbeat;

extern http_parser_settings bb_http_parser_settings;

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
	bbsr->content_length = ULLONG_MAX;

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

/*

	a session can be closed on I/O error

*/

static void bb_session_clear(struct bb_session *bbs) {
	int i;
	struct bb_connection *bbc = bbs->connection;

	// remove the session from the hash table
        bb_sht_remove(bbs);
                struct bb_session_request *bbsr = bbs->requests_head;
                while(bbsr) {
                        // in spdy mode, the first header is empty
                        for(i=bbc->spdy;i<=bbsr->header_pos;i++) {
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
                        bb_zmq_send_msg(bbs->dealer->identity, bbs->dealer->len, (char *) &bbs->uuid_part1, BB_UUID_LEN, "end", 3, "", 0);
                }

}

void bb_session_close(struct bb_session *bbs) {
	struct bb_connection *bbc = bbs->connection;
	bb_session_clear(bbs);	

	// first one ?
	if (bbs == bbc->sessions_head) {
		bbc->sessions_head = bbs->conn_next;
	}
	// last one ?
	if (bbs == bbc->sessions_tail) {
		bbc->sessions_tail = bbs->conn_prev;
	}

	if (bbs->conn_prev) {
		bbs->conn_prev->next = bbs->conn_next;
	}

	if (bbs->conn_next) {
		bbs->conn_next->prev = bbs->conn_prev;
	}

	free(bbs);
}

void bb_connection_close(struct bb_connection *bbc) {
	int i;
	ev_io_stop(blastbeat.loop, &bbc->reader.reader);
	ev_io_stop(blastbeat.loop, &bbc->writer.writer);
	if (bbc->ssl) {
		// this should be better managed, but why wasting resources ?
		// just ignore its return value
		SSL_shutdown(bbc->ssl);
		SSL_free(bbc->ssl);
	}
	close(bbc->fd);

	if (bbc->spdy) {
		deflateEnd(&bbc->spdy_z_in);
		deflateEnd(&bbc->spdy_z_out);
	}


	// remove sessions	

	struct bb_session *bbs = bbc->sessions_head;
	while(bbs) {
		bb_session_clear(bbs);
		struct bb_session *old_bbs = bbs;
		bbs = bbs->next;
		free(old_bbs);
	}

	// remove the writer queue
	struct bb_writer_item *bbwi = bbc->writer.head;
	while(bbwi) {
		struct bb_writer_item *old_bbwi = bbwi;	
		bbwi = bbwi->next;
		if (old_bbwi->free_it) {
			free(old_bbwi->buf);
		}
		free(old_bbwi);
	}

	free(bbc);
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

int bb_strcmp(char *str1, size_t str1len, char *str2, size_t str2len) {
	if (str1len != str2len) return -1;
	return memcmp(str1, str2, str1len);
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

struct bb_dealer *bb_get_dealer(struct bb_acceptor *acceptor, char *name, size_t len) {
	struct bb_virtualhost *vhost = acceptor->vhosts;
	while(vhost) {
		if (!bb_stricmp(name, len, vhost->name, vhost->len)) {
			return vhost->dealers;
		}
		vhost = vhost->next;
	}
	return NULL;
}

ssize_t bb_http_read(struct bb_connection *bbc, char *buf, size_t len) {
	return read(bbc->fd, buf, len);
}

ssize_t bb_http_write(struct bb_connection *bbc, char *buf, size_t len) {
	return write(bbc->fd, buf, len);
}

static void read_callback(struct ev_loop *loop, struct ev_io *w, int revents) {

	char buf[8192];
	ssize_t len;
	struct bb_reader *bbr = (struct bb_reader *) w;
	struct bb_connection *bbc = bbr->connection ;
	len = bbc->acceptor->read(bbc, buf, 8192);
	if (len > 0) {
		if (!bbc->spdy) {
			// in HTTP connections, only one session is allowed
			if (!bbc->sessions_head) {
				bbc->sessions_head = bb_session_new(bbc);	
			}
			struct bb_session *bbs = bbc->sessions_head;
			if (!bbs) goto clear;
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
		}
		else {
			if (bb_manage_spdy(bbc, buf, len)) {
				goto clear;
			}
		}
		//printf("res = %d\n", res);	
		return;
	}
	
	if (len == 0) {
		goto clear;
	}
	if (errno == EINPROGRESS || errno == EAGAIN || errno == EWOULDBLOCK)
		return;
	perror("read_callback error");
	
clear:
	bb_connection_close(bbc);
}

struct bb_session *bb_session_new(struct bb_connection *bbc) {
	struct bb_session *bbs = malloc(sizeof(struct bb_session));
	if (!bbs) {
		bb_error("malloc()");
		return NULL;
	}
	memset(bbs, 0, sizeof(struct bb_session));
	// put the session in the hashtable
	bb_sht_add(bbs);
	// prepare for allocating a new request
	bbs->new_request = 1;
	// link to the connection
	bbs->connection = bbc;
	if (!bbc->sessions_head) {
		bbc->sessions_head = bbs;
		bbc->sessions_tail = bbs;
	}
	else {
		bbs->conn_prev = bbc->sessions_tail;
		bbc->sessions_tail = bbs;
		bbs->conn_prev->next = bbs;
	}

	return bbs;
}

static void accept_callback(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct bb_acceptor *acceptor = (struct bb_acceptor *) w;
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

	struct bb_connection *bbc = malloc(sizeof(struct bb_connection));
	if (!bbc) {
		perror("malloc()");
		close(client);
		return;
	}
	memset(bbc, 0, sizeof(struct bb_connection));
	bbc->fd = client;
	bbc->acceptor = acceptor;
	// ssl context ?
	if (bbc->acceptor->ctx) {
		bbc->ssl = SSL_new(acceptor->ctx);
		SSL_set_ex_data(bbc->ssl, blastbeat.ssl_index, bbc);
		SSL_set_fd(bbc->ssl, bbc->fd);
		SSL_set_accept_state(bbc->ssl);
	}
	ev_io_init(&bbc->reader.reader, read_callback, client, EV_READ);
	bbc->reader.connection = bbc;
	ev_io_init(&bbc->writer.writer, bb_wq_callback, client, EV_WRITE);
	bbc->writer.connection = bbc;

	ev_io_start(loop, &bbc->reader.reader);
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

static void drop_privileges() {

	if (getuid() != 0) goto print;

	// setgid
	struct group *grp = getgrnam(blastbeat.gid);
	if (grp) {
		if (setgid(grp->gr_gid)) {
			bb_error_exit("unable to drop privileges: setgid()");
		}
	}
	else {
		if (setgid((gid_t)atoi(blastbeat.gid))) {
			bb_error_exit("unable to drop privileges: setgid()");
		}
	}

	// setuid
	struct passwd *pwd = getpwnam(blastbeat.uid);
	if (pwd) {
		if (setuid(pwd->pw_uid)) {
			bb_error_exit("unable to drop privileges: setuid()");
		}
	}
	else {
		if (setuid((uid_t)atoi(blastbeat.uid))) {
			bb_error_exit("unable to drop privileges: setuid()");
		}
	}

print:

	fprintf(stdout,"\nuid: %d\n", (int) getuid());
	fprintf(stdout,"gid: %d\n", (int) getgid());

};

static void bb_acceptor_bind(struct bb_acceptor *acceptor) {

	int server = socket(acceptor->addr.in.sa_family, SOCK_STREAM, 0);
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

        if (bind(server, &acceptor->addr.in, acceptor->addr_len)) {
                bb_error_exit("unable to bind to address: bind()");
        }

        if (listen(server, 100) < 0) {
                bb_error_exit("unable to put socket in listen mode: listen()");
        }

        if (bb_nonblock(server)) {
                fprintf(stderr,"unable to put socket in non-blocking mode\n");
                exit(1);
        }

	ev_io_init(&acceptor->acceptor, accept_callback, server, EV_READ);	
	ev_io_start(blastbeat.loop, &acceptor->acceptor);


	struct bb_virtualhost *vhost = acceptor->vhosts;
        while(vhost) {
                vhost->pinger.vhost = vhost;
                ev_timer_init(&vhost->pinger.pinger, pinger_cb, blastbeat.ping_freq, blastbeat.ping_freq);
                ev_timer_start(blastbeat.loop, &vhost->pinger.pinger);
                vhost = vhost->next;
        }

}

/*

the first acceptor has all of the vhost

scan all of the vhost in unshared acceptors
and remove them from the first (the shared one)

finally assign the shared vhost pointer to all of the shared acceptors

*/

static struct bb_virtualhost *bb_get_vhost(struct bb_virtualhost *bbvh, char *name, size_t len) {
	while(bbvh) {
		if (bbvh->len == len && bbvh->name == name) {
			return bbvh;
		}
		bbvh = bbvh->next;
	}

	return NULL;
}

static void bb_remove_unshared_vhost(struct bb_virtualhost *vhost) {
	struct bb_virtualhost *all_vhosts = blastbeat.acceptors->vhosts;
	struct bb_virtualhost *prev = NULL;
	while(all_vhosts) {
		// here we only need to compare name pointers
		if (all_vhosts->name == vhost->name) {
			if (!prev) {
				blastbeat.acceptors->vhosts = all_vhosts->next;
			}
			else {
				prev->next = all_vhosts->next;
			}
			free(all_vhosts);
			return;
		}
		prev = all_vhosts;
		all_vhosts = prev->next;
	}
}

static struct bb_virtualhost *bb_vhost_map_to_acceptor(struct bb_acceptor *acceptor, struct bb_virtualhost *vhost) {
	struct bb_virtualhost *v = bb_get_vhost(acceptor->vhosts, vhost->name, vhost->len);
	if (v) return v;

	v = malloc(sizeof(struct bb_virtualhost));
	if (!v) {
		bb_error("malloc()");
		return NULL;
	}
	memcpy(v, vhost, sizeof(struct bb_virtualhost));
	// fix the new object
	v->next = NULL;

	if (!acceptor->vhosts) {
		acceptor->vhosts = v;
		return v;
	}
	else {
		struct bb_virtualhost *vhosts = acceptor->vhosts;
		while(vhosts) {
			if (!vhosts->next) {
				vhosts->next = v;
				return v;
			}
			vhosts = vhosts->next;
		}
	}

	return NULL;
}

static void bb_acceptors_fix() {

	struct bb_acceptor *acceptor = blastbeat.acceptors->next;
	while(acceptor) {
		if (!acceptor->shared) {
			struct bb_str_list *mapped_vhosts = acceptor->mapped_vhosts;
			while(mapped_vhosts) {
				struct bb_virtualhost *vh = bb_get_vhost(blastbeat.acceptors->vhosts, mapped_vhosts->name, mapped_vhosts->len);
				if (!bb_vhost_map_to_acceptor(acceptor, vh)) {
					fprintf(stderr,"unable to map virtualhost to acceptor\n");
					exit(1);
				}
				mapped_vhosts = mapped_vhosts->next;
				bb_remove_unshared_vhost(vh);
			}
		}
		acceptor = acceptor->next;
	}

	// now re-use the same (main) shared list for all of the shared acceptors
	acceptor = blastbeat.acceptors->next;
	while(acceptor) {
                if (acceptor->shared) {
			acceptor->vhosts = blastbeat.acceptors->vhosts;
		}
		acceptor = acceptor->next;
	}
}

static void bb_assign_ssl(struct bb_acceptor *acceptor, struct bb_virtualhost *vhost) {

	if (!acceptor->ctx) return;

	char *certificate = blastbeat.ssl_certificate;
	if (vhost->ssl_certificate) certificate = vhost->ssl_certificate;

	char *key = blastbeat.ssl_key;
	if (vhost->ssl_key) key = vhost->ssl_key;

	if (!certificate) {
		fprintf(stderr,"you have not specified a valid SSL certificate\n");
		exit(1);
	}

	if (!key) {
		fprintf(stderr,"you have not specified a valid SSL key\n");
		exit(1);
	}

	if (SSL_CTX_use_certificate_file(acceptor->ctx, certificate, SSL_FILETYPE_PEM) <= 0) {
                fprintf(stderr, "unable to assign ssl certificate %s\n", certificate);
                exit(1);
        }	

	BIO *bio = BIO_new_file(certificate, "r");
        if (bio) {
                DH *dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
                BIO_free(bio);
                if (dh) {
                        SSL_CTX_set_tmp_dh(acceptor->ctx, dh);
                        DH_free(dh);
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
#ifdef NID_X9_62_prime256v1
                        EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                        SSL_CTX_set_tmp_ecdh(acceptor->ctx, ecdh);
                        EC_KEY_free(ecdh);
#endif
#endif
#endif
                }
        }

        if (SSL_CTX_use_PrivateKey_file(acceptor->ctx, key, SSL_FILETYPE_PEM) <= 0) {
                fprintf(stderr, "unable to assign key file %s\n", key);
                exit(1);
        }

}

int main(int argc, char *argv[]) {

	if (argc < 2) {
		fprintf(stderr, "syntax: blastbeat <configfile>\n");
		exit(1);
	}

	signal(SIGPIPE, SIG_IGN);

	// set default values
	blastbeat.ping_freq = 3.0;
	blastbeat.sht_size = 65536;
	blastbeat.uid = "nobody";
	blastbeat.gid = "nogroup";
	blastbeat.max_hops = 10;
	bb_ini_config(argv[1]);

	// validate config
	if (!blastbeat.acceptors) {
		fprintf(stderr, "config error: please specify at least one 'bind' directive\n");
		exit(1);
	}

	// fix acceptors/vhosts
	bb_acceptors_fix();

	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl)) {
		bb_error_exit("unable to get the maximum file descriptors number: getrlimit()");
	}

	blastbeat.max_fd = rl.rlim_cur;

	blastbeat.sht = malloc(sizeof(struct bb_session_entry) * blastbeat.sht_size);
	if (!blastbeat.sht) {
		bb_error_exit("unable to allocate sessions hashtable: malloc()");
	}
	memset(blastbeat.sht, 0, sizeof(struct bb_session_entry) * blastbeat.sht_size);

	blastbeat.loop = EV_DEFAULT;

	// report config, bind sockets and assign ssl keys/certificates
	struct bb_acceptor *acceptor = blastbeat.acceptors;
	fprintf(stdout,"*** starting BlastBeat ***\n");
	while(acceptor) {
		fprintf(stdout, "\n[acceptor %s]\n", acceptor->name);
		bb_acceptor_bind(acceptor);
		struct bb_virtualhost *vhost = acceptor->vhosts;
		while(vhost) {
			fprintf(stdout, "%s\n", vhost->name);
			bb_assign_ssl(acceptor, vhost);
			vhost = vhost->next;
		}
		acceptor = acceptor->next;
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

	drop_privileges();

	ev_io_init(&blastbeat.event_zmq, bb_zmq_receiver, blastbeat.zmq_fd, EV_READ);
	ev_io_start(blastbeat.loop, &blastbeat.event_zmq);

	fprintf(stdout,"\n*** BlastBeat is ready ***\n");

	ev_loop(blastbeat.loop, 0);
	return 0;

}
