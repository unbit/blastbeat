#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

ssize_t bb_ssl_read(struct bb_connection *bbc, char *buf, size_t len) {

	int ret = SSL_read(bbc->ssl, buf, len);
        if (ret > 0) {
		// came back to READ
		ev_io_stop(blastbeat.loop, &bbc->reader.reader);
		ev_io_set(&bbc->reader.reader, bbc->fd, EV_READ);
		ev_io_start(blastbeat.loop, &bbc->reader.reader);
                return ret;
        }
        if (ret == 0) {
		return 0;
	}
        int err = SSL_get_error(bbc->ssl, ret);

        if (err == SSL_ERROR_WANT_READ) {
		ev_io_stop(blastbeat.loop, &bbc->reader.reader);
		ev_io_set(&bbc->reader.reader, bbc->fd, EV_READ);
		ev_io_start(blastbeat.loop, &bbc->reader.reader);
                errno = EINPROGRESS;
                return -1;
        }

        else if (err == SSL_ERROR_WANT_WRITE) {
		ev_io_stop(blastbeat.loop, &bbc->reader.reader);
		ev_io_set(&bbc->reader.reader, bbc->fd, EV_WRITE);
		ev_io_start(blastbeat.loop, &bbc->reader.reader);
                errno = EINPROGRESS;
                return -1;
        }

        else if (err == SSL_ERROR_SYSCALL) {
                bb_error("SSL_read()");
        }

        else if (err == SSL_ERROR_SSL) {
                ERR_print_errors_fp(stderr);
        }

        return -1;


}

ssize_t bb_ssl_write(struct bb_connection *bbc, char *buf, size_t len) {
        int ret = SSL_write(bbc->ssl, buf, len);
        if (ret > 0) {
		// came back to WRITE
		ev_io_stop(blastbeat.loop, &bbc->writer.writer);
		ev_io_set(&bbc->writer.writer, bbc->fd, EV_WRITE);
		ev_io_start(blastbeat.loop, &bbc->writer.writer);
                return ret;
        }
        if (ret == 0) return 0;
        int err = SSL_get_error(bbc->ssl, ret);

        if (err == SSL_ERROR_WANT_READ) {
		ev_io_stop(blastbeat.loop, &bbc->writer.writer);
		ev_io_set(&bbc->writer.writer, bbc->fd, EV_READ);
		ev_io_start(blastbeat.loop, &bbc->writer.writer);
                errno = EINPROGRESS;
                return -1;
        }
        else if (err == SSL_ERROR_WANT_WRITE) {
		ev_io_stop(blastbeat.loop, &bbc->writer.writer);
		ev_io_set(&bbc->writer.writer, bbc->fd, EV_WRITE);
		ev_io_start(blastbeat.loop, &bbc->writer.writer);
                errno = EINPROGRESS;
                return -1;
        }

        else if (err == SSL_ERROR_SYSCALL) {
                bb_error("SSL_write()");
        }

        else if (err == SSL_ERROR_SSL) {
                ERR_print_errors_fp(stderr);
        }

        return -1;
}


#ifdef OPENSSL_NPN_UNSUPPORTED
static int bb_ssl_npn(SSL *ssl, const unsigned char **data, unsigned int *len, void *arg) {
        *data = (const unsigned char *) "\x06spdy/3\x08http/1.1\x08http/1.0";
        *len = strlen((const char *) *data);
        return SSL_TLSEXT_ERR_OK;
}
#endif

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
static int bb_ssl_servername(SSL *ssl,int *ad, void *arg) {
	const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!servername) return SSL_TLSEXT_ERR_NOACK;
	struct bb_connection *bbc = SSL_get_ex_data(ssl, blastbeat.ssl_index);
	struct bb_acceptor *bba = bbc->acceptor;
	size_t servername_len = strlen(servername);

	struct bb_virtualhost *vhost = NULL;
	struct bb_hostname *bbhn = NULL;

	if (bba->addr.in4.sin_port != htons(443) && !strchr(servername, ':')) {
		size_t port_len = strlen(bba->port_str);
		char *new_sn = bb_alloc(servername_len+port_len);
		if (!new_sn) return SSL_TLSEXT_ERR_NOACK;
		memcpy(new_sn, servername, servername_len);
		memcpy(new_sn + servername_len, bba->port_str, port_len);

		vhost = bb_vhost_get(new_sn, servername_len+port_len, &bbhn);
		bb_free(new_sn, servername_len+port_len);
	}
	else {
		vhost = bb_vhost_get((char *)servername, servername_len, &bbhn);
	}

	if (!vhost) return SSL_TLSEXT_ERR_NOACK;
	// per vhost-context is required to decrypt keys sent by dealers
	if (!vhost->ctx) return SSL_TLSEXT_ERR_NOACK;

	// prefer dealer-defined context
	if (bbhn->ctx) {
		SSL_set_SSL_CTX(ssl, bbhn->ctx);
		return SSL_TLSEXT_ERR_OK;
	}


	SSL_set_SSL_CTX(ssl, vhost->ctx);

	return SSL_TLSEXT_ERR_OK;
}
#endif

SSL_CTX *bb_new_ssl_ctx() {

        SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
        if (!ctx) {
                fprintf(stderr, "unable to initialize SSL context: SSL_CTX_new()");
		return NULL;
        }

        long ssloptions = SSL_OP_NO_SSLv2 | SSL_OP_ALL | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
        // disable compression (if possibile)
#ifdef SSL_OP_NO_COMPRESSION
        ssloptions |= SSL_OP_NO_COMPRESSION;
#endif
        SSL_CTX_set_options(ctx, ssloptions);

        // release/reuse buffers as soon as possibile
#ifdef SSL_MODE_RELEASE_BUFFERS
        SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

        if (SSL_CTX_set_cipher_list(ctx, "HIGH") == 0) {
                fprintf(stderr,"unable to set SSL ciphers: SSL_CTX_set_cipher_list()");
		SSL_CTX_free(ctx);
		return NULL;
        }

        SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

        SSL_CTX_set_info_callback(ctx, bb_ssl_info_cb);
#ifdef OPENSSL_NPN_UNSUPPORTED
        SSL_CTX_set_next_protos_advertised_cb(ctx, bb_ssl_npn, NULL);
#endif
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	SSL_CTX_set_tlsext_servername_callback(ctx, bb_ssl_servername);
#else
#warning TLS SNI support not available !!!
#endif

        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);

	return ctx;
}


void bb_socket_ssl(struct bb_acceptor *acceptor) {

        if (!blastbeat.ssl_initialized) {
                OPENSSL_config(NULL);
                SSL_library_init();
                SSL_load_error_strings();
                OpenSSL_add_all_algorithms();
                blastbeat.ssl_initialized = 1;
                blastbeat.ssl_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        }

	acceptor->ctx = bb_new_ssl_ctx();
	if (!acceptor->ctx) {
		exit(1);
	}

        acceptor->read = bb_ssl_read;
        acceptor->write = bb_ssl_write;
}

//create an ssl context for an hostname
int bb_add_ssl_context(struct bb_hostname *bbhn, char *buf, size_t len) {
}
