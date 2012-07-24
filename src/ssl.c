#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

ssize_t bb_ssl_read(struct bb_session *bbs, char *buf, size_t len) {

	int ret = SSL_read(bbs->ssl, buf, len);
        if (ret > 0) {
		// came back to READ
		ev_io_stop(blastbeat.loop, &bbs->reader.reader);
		ev_io_set(&bbs->reader.reader, bbs->fd, EV_READ);
		ev_io_start(blastbeat.loop, &bbs->reader.reader);
                return ret;
        }
        if (ret == 0) {
		return 0;
	}
        int err = SSL_get_error(bbs->ssl, ret);

        if (err == SSL_ERROR_WANT_READ) {
		ev_io_stop(blastbeat.loop, &bbs->reader.reader);
		ev_io_set(&bbs->reader.reader, bbs->fd, EV_READ);
		ev_io_start(blastbeat.loop, &bbs->reader.reader);
                errno = EINPROGRESS;
                return -1;
        }

        else if (err == SSL_ERROR_WANT_WRITE) {
		ev_io_stop(blastbeat.loop, &bbs->reader.reader);
		ev_io_set(&bbs->reader.reader, bbs->fd, EV_WRITE);
		ev_io_start(blastbeat.loop, &bbs->reader.reader);
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

ssize_t bb_ssl_write(struct bb_session *bbs, char *buf, size_t len) {
        int ret = SSL_write(bbs->ssl, buf, len);
        if (ret > 0) {
		// came back to WRITE
		ev_io_stop(blastbeat.loop, &bbs->writer.writer);
		ev_io_set(&bbs->writer.writer, bbs->fd, EV_WRITE);
		ev_io_start(blastbeat.loop, &bbs->writer.writer);
                return ret;
        }
        if (ret == 0) return 0;
        int err = SSL_get_error(bbs->ssl, ret);

        if (err == SSL_ERROR_WANT_READ) {
		ev_io_stop(blastbeat.loop, &bbs->writer.writer);
		ev_io_set(&bbs->writer.writer, bbs->fd, EV_READ);
		ev_io_start(blastbeat.loop, &bbs->writer.writer);
                errno = EINPROGRESS;
                return -1;
        }
        else if (err == SSL_ERROR_WANT_WRITE) {
		ev_io_stop(blastbeat.loop, &bbs->writer.writer);
		ev_io_set(&bbs->writer.writer, bbs->fd, EV_WRITE);
		ev_io_start(blastbeat.loop, &bbs->writer.writer);
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

