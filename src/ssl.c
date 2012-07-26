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
        *data = "\x06spdy/2\x08http/1.1\x08http/1.0";
        *len = strlen(*data);
        return SSL_TLSEXT_ERR_OK;
}
#endif

void bb_socket_ssl(struct bb_acceptor *acceptor) {

        if (!blastbeat.ssl_initialized) {
                OPENSSL_config(NULL);
                SSL_library_init();
                SSL_load_error_strings();
                OpenSSL_add_all_algorithms();
                blastbeat.ssl_initialized = 1;
                blastbeat.ssl_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        }

        acceptor->ctx = SSL_CTX_new(SSLv23_server_method());
        if (!acceptor->ctx) {
                fprintf(stderr, "unable to initialize SSL context: SSL_CTX_new()");
                exit(1);
        }

        long ssloptions = SSL_OP_NO_SSLv2 | SSL_OP_ALL | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
        // disable compression (if possibile)
#ifdef SSL_OP_NO_COMPRESSION
        ssloptions |= SSL_OP_NO_COMPRESSION;
#endif
        SSL_CTX_set_options(acceptor->ctx, ssloptions);

        // release/reuse buffers as soon as possibile
#ifdef SSL_MODE_RELEASE_BUFFERS
        SSL_CTX_set_mode(acceptor->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

        if (SSL_CTX_set_cipher_list(acceptor->ctx, "HIGH") == 0) {
                fprintf(stderr,"unable to set SSL ciphers: SSL_CTX_set_cipher_list()");
                exit(1);
        }

        SSL_CTX_set_options(acceptor->ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

        SSL_CTX_set_info_callback(acceptor->ctx, bb_ssl_info_cb);
#ifdef OPENSSL_NPN_UNSUPPORTED
        SSL_CTX_set_next_protos_advertised_cb(acceptor->ctx, bb_ssl_npn, NULL);
#endif

        SSL_CTX_set_session_cache_mode(acceptor->ctx, SSL_SESS_CACHE_SERVER);

        acceptor->read = bb_ssl_read;
        acceptor->write = bb_ssl_write;
}

