#include "../blastbeat.h"

struct blastbeat_server blastbeat;

/*

	--- BlastBeat sessions ---

a persistent session is not removed from the hashtable, but a timer is
attached to it. The timer is reset whenever some kind of activity is triggered on the sessions.
If the timeout expires, the sessions is definitely removed.

PAY ATTENTION:

persistent sessions can be without a related connection
persistent sessions get the request/response datas cleared after each usage

*/


void bb_session_close(struct bb_session *bbs) {
	struct bb_connection *bbc = bbs->connection;

	if (!bbs->persistent) {
		// stop the death timer before destrying the session
		ev_timer_stop(blastbeat.loop, &bbs->death_timer);
                bb_sht_remove(bbs);
	}

        // clear the HTTP request structure
        bb_initialize_request(bbs);

	// clear dynamic memory areas (if required)
	if (bbs->push_queue) {
		bb_free(bbs->push_queue, bbs->push_queue_len);
	}

        // remove groups and pipes (if not persistent)
        if (!bbs->persistent) {
                struct bb_session_group *bbsg = bbs->groups;
                while(bbsg) {
                        struct bb_session_group *current_bbsg = bbsg;
                        bbsg = bbsg->next;
                        bb_session_leave_group(bbs, current_bbsg->group);
                }

		struct bb_pipe *bbp = bbs->pipes_head;
		while(bbp) {
			struct bb_pipe *bbp_next = bbp->next;
			bb_free(bbp, sizeof(struct bb_pipe));
			bbp = bbp_next;
		}

                // if linked to a dealer (and not in stealth mode), send a 'end' message
                if (bbs->dealer && !bbs->stealth) {
                        bb_zmq_send_msg(bbs, bbs->dealer->identity, bbs->dealer->len, (char *) &bbs->uuid_part1, BB_UUID_LEN, "end", 3, "", 0);
                }
        }

	// detaching the session for the related connection
	if (!bbc) goto clear;

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

	bbs->connection = NULL;
	bbs->conn_prev = NULL;
	bbs->conn_next = NULL;

clear:

	if (!bbs->persistent)
		bb_free(bbs, sizeof(struct bb_session));
}

/*

closing a connection means freeing/stopping the write queue and destroying all of the associated (non-persistent) sessions

connection close is triggered:
	when the client closes the connection
	on network/protocol error
	on non-HTTP/1.1 sessions end
*/

void bb_connection_close(struct bb_connection *bbc) {

	// a connection could be null (for persistent sessions...)
	if (!bbc) return;

	// stop the timer
	ev_timer_stop(blastbeat.loop, &bbc->timeout);
	// stop I/O
	ev_io_stop(blastbeat.loop, &bbc->reader.reader);
	ev_io_stop(blastbeat.loop, &bbc->writer.writer);
	// clear SSL if required
	if (bbc->ssl) {
		// this should be better managed, but why wasting resources ?
		// just ignore its return value
		SSL_shutdown(bbc->ssl);
		SSL_free(bbc->ssl);
	}
	// close the socket
	close(bbc->fd);

	// free SPDY resources
	if (bbc->spdy) {
		deflateEnd(&bbc->spdy_z_in);
		deflateEnd(&bbc->spdy_z_out);
	}

	// close sessions	
	struct bb_session *next_bbs, *bbs = bbc->sessions_head;
	while(bbs) {
		next_bbs = bbs->conn_next;
		bb_session_close(bbs);
		bbs = next_bbs;
	}

	// remove the writer queue
	// no fear of it as the write callback is stopped
	struct bb_writer_item *bbwi = bbc->writer.head;
	while(bbwi) {
		struct bb_writer_item *old_bbwi = bbwi;	
		bbwi = bbwi->next;
		if ((old_bbwi->flags & BB_WQ_FREE) && old_bbwi->len > 0) {
			bb_free(old_bbwi->buf, old_bbwi->len);
		}
		bb_free(old_bbwi, sizeof(struct bb_writer_item));
	}

	bb_free(bbc, sizeof(struct bb_connection));
	blastbeat.active_connections--;
}

int bb_set_dealer(struct bb_session *bbs, char *name, size_t len) {
	// get the virtualhost from the hostname
	struct bb_virtualhost *vhost = bb_vhost_get(name, len);
	if (!vhost) return -1;

	// check if the virtualhost is allowed in that acceptor
	int found = 0;
	struct bb_acceptor *acceptor = bbs->connection->acceptor;
	struct bb_vhost_acceptor *allowed_acceptor = vhost->acceptors;
	while(allowed_acceptor) {
		if (allowed_acceptor->acceptor == acceptor) {
			found = 1;
			break;
		}
		allowed_acceptor = allowed_acceptor->next;
	}
	if (!found) return -1;

	// set the connection timeout for the virtualhost (if specified)
	if (bbs->connection && vhost->timeout > 0) {
		bbs->connection->timeout_value = vhost->timeout;	
	}

	struct bb_vhost_dealer *bbvd = vhost->dealers;
	struct bb_dealer *best_dealer = NULL;
	while(bbvd) {
		if (bbvd->dealer->status == BLASTBEAT_DEALER_OFF) goto next;
		if (!best_dealer) {
			best_dealer = bbvd->dealer;
		}
		else if (bbvd->dealer->load < best_dealer->load) {
			best_dealer = bbvd->dealer;
		}
next:
		bbvd = bbvd->next;
	}
	
	if (!best_dealer) return -1;
	best_dealer->load++;
	bbs->vhost = vhost;
	// increase only if it is not a moving session
	if (!bbs->dealer) {
		// increase here !!! (to avoid wrong call of -- on overload)
		bbs->vhost->active_sessions++;
		if (bbs->vhost->max_sessions > 0 && bbs->vhost->active_sessions > bbs->vhost->max_sessions) {
			fprintf(stderr,"!!! maximum number of sessions (%llu) for virtualhost \"%.*s\" reached !!!\n", (unsigned long long) bbs->vhost->max_sessions, (int) bbs->vhost->len, bbs->vhost->name);
			return -1;
		}
	}
	bbs->dealer = best_dealer;
	return 0;
}

void bb_connection_reset_timer(struct bb_connection *bbc) {
	ev_timer_stop(blastbeat.loop, &bbc->timeout);
	ev_timer_set(&bbc->timeout, bbc->timeout_value, 0.0);
	ev_timer_start(blastbeat.loop, &bbc->timeout);
}

void bb_session_reset_timer(struct bb_session *bbs, uint64_t t, int(*func)(struct bb_session *)) {
	ev_timer_stop(blastbeat.loop, &bbs->death_timer);
	bbs->death_timer_func = func;
	ev_timer_set(&bbs->death_timer, t, 0.0);
	ev_timer_start(blastbeat.loop, &bbs->death_timer);
}

static void bb_rd_callback(struct ev_loop *loop, struct ev_io *w, int revents) {

	char buf[BLASTBEAT_BUFSIZE];
	ssize_t len;
	struct bb_reader *bbr = (struct bb_reader *) w;
	struct bb_connection *bbc = bbr->connection ;

	// reset the timer
	bb_connection_reset_timer(bbc);

	len = bbc->acceptor->read(bbc, buf, BLASTBEAT_BUFSIZE);
	if (len > 0) {
		if (bbc->func(bbc, buf, len)) goto clear;
		return;
	}
	
	if (len == 0) {
		goto clear;
	}
	if (errno == EINPROGRESS || errno == EAGAIN || errno == EWOULDBLOCK)
		return;
	bb_error("read callback error: ");
clear:
	bb_connection_close(bbc);
}

static void connection_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
	struct bb_connection *bbc = (struct bb_connection *) w;
	bb_connection_close(bbc);
}

static void session_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
	struct bb_session *bbs = (struct bb_session *) w;

	if (bbs->death_timer_func) {
		if (bbs->death_timer_func(bbs)) {
			return;
		}
	}
	// completely destroy the session
	bbs->persistent = 0;
	bb_session_close(bbs);
}

// each session has a request structure, this strcture can be cleared multiple times
void bb_initialize_request(struct bb_session *bbs) {
	size_t i;
	// free already used resources
	if (bbs->request.initialized) {
		if (bbs->request.uwsgi_buf) {
			bb_free(bbs->request.uwsgi_buf, bbs->request.uwsgi_len);
		}
		if (bbs->request.websocket_message_queue) {
			bb_free(bbs->request.websocket_message_queue, bbs->request.websocket_message_queue_len);
		}
		for(i=0;i<=bbs->request.header_pos;i++) {
			if (bbs->request.headers[i].key)
				bb_free(bbs->request.headers[i].key, bbs->request.headers[i].keylen);
			if (bbs->request.headers[i].value)
				bb_free(bbs->request.headers[i].value, bbs->request.headers[i].vallen);
		}
		// clear all
		memset(&bbs->request, 0, sizeof(struct bb_request));
	}

	http_parser_init(&bbs->request.parser, HTTP_REQUEST);
	bbs->request.parser.data = bbs;
	bbs->request.last_was_value = 1;

	bbs->request.initialized = 1;
}

// each session has a response structure, this strcture can be cleared multiple times
void bb_initialize_response(struct bb_session *bbs) {
	if (bbs->response.initialized) {
		memset(&bbs->response, 0, sizeof(struct bb_response));
	}
	http_parser_init(&bbs->response.parser, HTTP_RESPONSE);
        bbs->response.parser.data = bbs;
	bbs->response.last_was_value = 1;

	bbs->response.initialized = 1;
}


// allocate a new session
struct bb_session *bb_session_new(struct bb_connection *bbc) {
	if (blastbeat.active_sessions+1 > blastbeat.max_sessions) {
		fprintf(stderr,"!!! maximum number of total sessions (%llu) reached !!!\n", (unsigned long long) blastbeat.max_sessions);
		return NULL;
	}
	struct bb_session *bbs = bb_alloc(sizeof(struct bb_session));
	if (!bbs) {
		return NULL;
	}
	memset(bbs, 0, sizeof(struct bb_session));
	// put the session in the hashtable
	bb_sht_add(bbs);
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

	// by default set the HTTP hooks
	bbs->send_headers = bb_http_send_headers;
	bbs->send_end = bb_http_send_end;
	bbs->send_body = bb_http_send_body;
	bbs->recv_body = bb_http_recv_body;
	bbs->send_cache_headers = bb_http_cache_send_headers;
	bbs->send_cache_body = bb_http_cache_send_body;

	ev_timer_init(&bbs->death_timer, session_timer_cb, 0.0, 0.0);

	blastbeat.active_sessions++;
	return bbs;
}

// this callback create a new connection object
static void bb_accept_callback(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct bb_acceptor *acceptor = (struct bb_acceptor *) w;
	union bb_addr addr;
	socklen_t sin_len = acceptor->addr_len;
	int client = accept(w->fd, (struct sockaddr *)&addr, &sin_len);
	if (client < 0) {
		perror("accept()");
		return;
	}

	if (bb_nonblock(client)) {
		close(client);
		return;
	}

	// generate a new connection object
	struct bb_connection *bbc = bb_alloc(sizeof(struct bb_connection));
	if (!bbc) {
		close(client);
		return;
	}
	memset(bbc, 0, sizeof(struct bb_connection));

	// copy the address structure
	memcpy(&bbc->addr, &addr, sizeof(union bb_addr));

	char *addr_ptr = (char *) &addr.in4.sin_addr.s_addr;
	if (addr.in.sa_family == AF_INET6) {
		addr_ptr = (char *) &addr.in6.sin6_addr.s6_addr;
	}

	if (!inet_ntop(addr.in.sa_family, addr_ptr, bbc->addr_str, INET6_ADDRSTRLEN)) {
		bb_error("ntop()");
	}

	// we could use the same address for ipv4 and ipv6
	if (snprintf(bbc->addr_port, 6, "%u", addr.in4.sin_port) < 1) {
		fprintf(stderr,"unable to get client port\n");
	}

	// for performance
	bbc->addr_str_len = strlen(bbc->addr_str);
	bbc->addr_port_len = strlen(bbc->addr_port);

	bbc->fd = client;
	bbc->acceptor = acceptor;
	// ssl context ?
	if (bbc->acceptor->ctx) {
		bbc->ssl = SSL_new(acceptor->ctx);
		SSL_set_ex_data(bbc->ssl, blastbeat.ssl_index, bbc);
		SSL_set_fd(bbc->ssl, bbc->fd);
		SSL_set_accept_state(bbc->ssl);
	}
	// set the HTTP parser by default
	bbc->func = bb_http_func;

	ev_io_init(&bbc->reader.reader, bb_rd_callback, client, EV_READ);
	bbc->reader.connection = bbc;
	ev_io_init(&bbc->writer.writer, bb_wq_callback, client, EV_WRITE);
	bbc->writer.connection = bbc;

	// prepare a low level connection timeout
	ev_timer_init(&bbc->timeout, connection_timer_cb, 0.0, 0.0);
	// set the deafult timeout
	bbc->timeout_value = blastbeat.timeout;

	blastbeat.active_connections++;

	ev_io_start(loop, &bbc->reader.reader);
}

// currently it only prints the number of active sessions and connections
static void stats_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
	uint64_t running_memory = blastbeat.allocated_memory-(blastbeat.startup_memory+blastbeat.cache_memory);
	fprintf(stderr,"active sessions: %llu active connections %llu running memory: %llu (%lluMB) cache memory: %llu (%lluMB) total memory: %lluMB\n", (unsigned long long) blastbeat.active_sessions, 
		(unsigned long long) blastbeat.active_connections,
		(unsigned long long) running_memory,
		(unsigned long long) running_memory/1024/1024,
		(unsigned long long) blastbeat.cache_memory,
		(unsigned long long) blastbeat.cache_memory/1024/1024,
		(unsigned long long) blastbeat.allocated_memory/1024/1024);
}

// the healthcheck system
static void pinger_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {

	struct bb_dealer *bbd = blastbeat.dealers;
	// get events before starting a potentially long write session
	ev_feed_event(blastbeat.loop, &blastbeat.event_zmq, EV_READ);
	ev_tstamp now = bb_now;
	while(bbd) {
		ev_tstamp delta = now - bbd->last_seen;
		if (delta >= blastbeat.ping_freq) {
			if (delta > (blastbeat.ping_freq * 3) && bbd->status == BLASTBEAT_DEALER_AVAILABLE) {
				bbd->status = BLASTBEAT_DEALER_OFF;
				fprintf(stderr,"node \"%s\" is OFF\n", bbd->identity);
			}
			bb_raw_zmq_send_msg(NULL, bbd->identity, bbd->len, "", 0, "ping", 4, "", 0);
		}
		if (!bbd->spawn_sent) {
			bb_raw_zmq_send_msg(NULL, bbd->identity, bbd->len, "", 0, "spawn", 5, "", 0);
			bbd->spawn_sent = 1;
		}
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

#ifdef TCP_DEFER_ACCEPT
	if (setsockopt(server, IPPROTO_TCP, TCP_DEFER_ACCEPT, &on, sizeof(int))) {
        	bb_error("setsockopt()");
        }
#elif defined(SO_ACCEPTFILTER)
	struct accept_filter_arg afa;
        strcpy(afa.af_name, "dataready");
        afa.af_arg[0] = 0;
        if (setsockopt(server, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(struct accept_filter_arg))) {
        	bb_error("setsockopt()");
	}
#endif


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

	ev_io_init(&acceptor->acceptor, bb_accept_callback, server, EV_READ);	
	ev_io_start(blastbeat.loop, &acceptor->acceptor);

}

/*

add vhosts to acceptors

*/

static void bb_acceptor_push_vhost(struct bb_acceptor *acceptor, struct bb_virtualhost *vhost) {
	struct bb_acceptor_vhost *last_vhost=NULL,*vhosts = acceptor->vhosts;
	while(vhosts) {
		if (vhosts->vhost == vhost)
			return;
		last_vhost = vhosts;
		vhosts = vhosts->next;
	}

	vhosts = bb_alloc(sizeof(struct bb_acceptor_vhost));
	if (!vhosts) {
		bb_error_exit("malloc()");
	}
	vhosts->vhost = vhost;
	vhosts->next = NULL;

	if (last_vhost) {
		last_vhost->next = vhosts;
	}
	else {
		acceptor->vhosts = vhosts;
	}
}

// this allocates memory for caching too
static void bb_vhosts_fix() {

	struct bb_virtualhost *vhosts = blastbeat.vhosts;
	while(vhosts) {
		struct bb_vhost_acceptor *acceptor = vhosts->acceptors;
		while(acceptor) {
			bb_acceptor_push_vhost(acceptor->acceptor, vhosts);
			acceptor = acceptor->next;
		}
		if (vhosts->cache_size > 0) {
			vhosts->cht_size = 65536;
			vhosts->cache = bb_alloc(sizeof(struct bb_cache_entry) * vhosts->cht_size);
			if (!vhosts->cache) {
				bb_error_exit("unable to allocate memory for caching: malloc()\n");
			}
			memset(vhosts->cache, 0, sizeof(struct bb_cache_entry) * vhosts->cht_size);
		}
		vhosts = vhosts->next;
	}

	// now push all of the shared acceptors to virtualhosts with empty acceptors list
	vhosts = blastbeat.vhosts;
	while(vhosts) {
		if (!vhosts->acceptors) {
			struct bb_acceptor *acceptor = blastbeat.acceptors;
			while(acceptor) {
				if (acceptor->shared) {
					bb_acceptor_push_vhost(acceptor, vhosts);
					// attach teh acceptor to the virtualhost too
					bb_vhost_push_acceptor(vhosts, acceptor);
				}
				acceptor = acceptor->next;
			}
		}
		vhosts = vhosts->next;
	}
}

static void bb_assign_cert(SSL_CTX *ctx, char *key, char *certificate) {

	if (SSL_CTX_use_certificate_file(ctx, certificate, SSL_FILETYPE_PEM) <= 0) {
                fprintf(stderr, "unable to assign ssl certificate %s\n", certificate);
                exit(1);
        }

        BIO *bio = BIO_new_file(certificate, "r");
        if (bio) {
                DH *dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
                BIO_free(bio);
                if (dh) {
                        SSL_CTX_set_tmp_dh(ctx, dh);
                        DH_free(dh);
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
#ifdef NID_X9_62_prime256v1
                        EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                        SSL_CTX_set_tmp_ecdh(ctx, ecdh);
                        EC_KEY_free(ecdh);
#endif
#endif
#endif
                }
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
                fprintf(stderr, "unable to assign key file %s\n", key);
                exit(1);
        }

}

static void bb_assign_ssl(struct bb_acceptor *acceptor, struct bb_virtualhost *vhost) {

	if (!acceptor->ctx) return;

	// create a new context, required for SNI
	vhost->ctx = bb_new_ssl_ctx();
	if (!vhost->ctx) {
		exit(1);
	}

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

	if (!acceptor->ctx_configured) {
		bb_assign_cert(acceptor->ctx, key, certificate);
		acceptor->ctx_configured = 1;
	}

	bb_assign_cert(vhost->ctx, key, certificate);
}

int main(int argc, char *argv[]) {

	if (argc < 2) {
		fprintf(stderr, "syntax: blastbeat <configfile>\n");
		exit(1);
	}

	signal(SIGPIPE, SIG_IGN);

	// set default values
	blastbeat.ping_freq = 3.0;
	blastbeat.stats_freq = 60.0;
	blastbeat.sht_size = 65536;
	blastbeat.uid = "nobody";
	blastbeat.gid = "nogroup";
	blastbeat.max_hops = 10;
	blastbeat.max_sessions = 10000;
	// 2GB max_memory
	blastbeat.max_memory = (uint64_t) 2048*1024*1024;
	// default 30 minutes timeout
	blastbeat.timeout = 1800;
	// clear the hostname hashtable (just for safety)
	memset(blastbeat.hnht, 0, sizeof(struct bb_hostname *) * BLASTBEAT_HOSTNAME_HTSIZE);
	// run the config parser
	bb_ini_config(argv[1]);

	// validate config
	if (!blastbeat.acceptors) {
		fprintf(stderr, "config error: please specify at least one 'bind' directive\n");
		exit(1);
	}

	if (!blastbeat.zmq) {
		fprintf(stderr, "config error: please specify at least one 'zmq' directive\n");
		exit(1);
	}

	// fix acceptors/vhosts/cache...
	bb_vhosts_fix();

	fprintf(stderr,"*** starting BlastBeat ***\n");

	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl)) {
		bb_error("unable to get the maximum file descriptors number: getrlimit()");
	}

	blastbeat.max_fd = rl.rlim_cur;
	if (blastbeat.max_fd < blastbeat.max_sessions*2) {
		rl.rlim_cur = blastbeat.max_sessions*2;
		rl.rlim_max = blastbeat.max_sessions*2;
		if (setrlimit(RLIMIT_NOFILE, &rl)) {
			bb_error("unable to set the maximum file descriptors number: setrlimit()");
			fprintf(stderr,"lowering max sessions to %llu\n", (unsigned long long) blastbeat.max_fd/2);
			blastbeat.max_sessions = blastbeat.max_fd/2;
		}	
		else {
			blastbeat.max_fd = rl.rlim_max;
		}
	}

	fprintf(stderr, "allowed sessions: %llu\n", (unsigned long long) blastbeat.max_sessions);

	blastbeat.sht = bb_alloc(sizeof(struct bb_session_entry) * blastbeat.sht_size);
	if (!blastbeat.sht) {
		bb_error_exit("unable to allocate sessions hashtable: malloc()");
	}
	memset(blastbeat.sht, 0, sizeof(struct bb_session_entry) * blastbeat.sht_size);
	

	blastbeat.loop = EV_DEFAULT;

	// report config, bind sockets and assign ssl keys/certificates
	struct bb_acceptor *acceptor = blastbeat.acceptors;
	while(acceptor) {
		fprintf(stdout, "\n[acceptor %s]\n", acceptor->name);
		bb_acceptor_bind(acceptor);
		struct bb_acceptor_vhost *vhost = acceptor->vhosts;
		while(vhost) {
			fprintf(stdout, "%s\n", vhost->vhost->name);
			bb_assign_ssl(acceptor, vhost->vhost);
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

	ev_prepare_init(&blastbeat.zmq_check, bb_zmq_check_cb);

	// the first ping is after 1 second
	ev_timer_init(&blastbeat.pinger, pinger_cb, 1.0, blastbeat.ping_freq);
        ev_timer_start(blastbeat.loop, &blastbeat.pinger);

	// report stats every 60 seconds
	ev_timer_init(&blastbeat.stats, stats_cb, blastbeat.stats_freq, blastbeat.stats_freq);
        ev_timer_start(blastbeat.loop, &blastbeat.stats);

	blastbeat.startup_memory = blastbeat.allocated_memory;
	fprintf(stdout,"\n*** BlastBeat is ready (%lluMB allocated) ***\n", (unsigned long long) blastbeat.startup_memory/1024/1024);
	
	ev_loop(blastbeat.loop, 0);
	return 0;

}
