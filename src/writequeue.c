#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

/*

	The BlastBeat write queue

	Non-blocking writes are pretty complex to manage
	This implementation uses a queue of buffers associated to an ev_io structure

	Whenever an item is put in the queue an ev_io writer will be start and it will try to
	write datas until it fails (returning EAGAIN or an incomplete write)

	The offset in each item is required for managing incomplete writes

*/
static int wq_push(struct bb_writer *bbw, char *buf, size_t len, int flags, struct bb_session *bbs) {

	
	// do not enqueue more than 8 megabytes (TODO configure that value)		
	if (bbw->len+len > 8*1024*1024) {
		fprintf(stderr,"too much queued datas\n");
		return -1;
	}

	struct bb_writer_item *bbwi = bb_alloc(sizeof(struct bb_writer_item));
	if (!bbwi) {
		bb_error("unable to allocate memory for a writequeue item: malloc()");
		return -1;
	}

	bbwi->buf = buf;
	bbwi->pos = 0;
	bbwi->len = len;
	bbwi->flags = flags;
	bbwi->session = bbs;
	bbwi->next = NULL;

	if (!bbw->head) {
		bbw->head = bbwi;
	}
	else {
		bbw->tail->next = bbwi;
	}

	bbw->tail = bbwi;
	bbw->len += len;
	return 0;
}

static void wq_decapitate(struct bb_writer *bbw) {

	struct bb_writer_item *head = bbw->head;
	bbw->head = head->next;
	// is it the last item ?
	if (head == bbw->tail) {
		bbw->tail = NULL;
		bbw->head = NULL;
	}
	if ((head->flags & BB_WQ_FREE) && head->len > 0) {
		bb_free(head->buf, head->len);
	}
	bb_free(head, sizeof(struct bb_writer_item));
}

void bb_wq_callback(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct bb_writer *bbw = (struct bb_writer *) w;
	struct bb_connection *bbc = bbw->connection;

	struct bb_writer_item *bbwi = bbw->head;
	while(bbwi) {
		if (bbwi->flags & BB_WQ_CLOSE) goto end;
		if (bbwi->flags & BB_WQ_EOS) goto end2;
		if (bbwi->len == 0) goto next;

		size_t bbw_len = bbwi->len-bbwi->pos;

		if (bbwi->session) {
			// bandwidth check
			uint64_t bandwidth = bbwi->session->vhost->bandwidth;
			if (bandwidth) {
				// if packet is bigger than bucket size, split it
				size_t available = bandwidth - bbwi->session->vhost->bandwidth_bucket;
				if (bbw_len > available) {
					bbw_len -= available;
				}
				// ok, we now have a valid chunk, can we send it ?
				// we have milliseconds resolution
				ev_tstamp now = bb_milliseconds;
				// too fast, we have to throttle
				if (now - bbwi->session->vhost->bandwidth_last_sent <= 0) {
				}
			}
		}

		ssize_t wlen = bbc->acceptor->write(bbc, bbwi->buf+bbwi->pos, bbw_len);
		if (wlen < 0) {
			if (errno == EINPROGRESS || errno == EAGAIN || errno == EWOULDBLOCK) {
				return ;
			}
			bb_error("unable to write to client: write()");
			goto end;
		}
		if (wlen == 0) {
			bb_error("client disconnected: write()");
			goto end;
		}

		// reset the connection activity timer on successfully sent
		bb_connection_reset_timer(bbc);

		// account transferred bytes to the virtualhost
		if (bbwi->session) {
			bbwi->session->vhost->tx+=wlen;
		}

		bbw->len -= wlen;

		if (wlen < bbwi->len-bbwi->pos) {
			bbwi->pos+=wlen;
			return;
		}
next:
		bbwi = bbwi->next;
		wq_decapitate(bbw);
	}
	ev_io_stop(blastbeat.loop, w);
	return;
end:
	bb_connection_close(bbc);
	return;
end2:
	// close the session (remember to decapitate, as other session will continue pushing)
	wq_decapitate(bbw);
	bb_session_close(bbwi->session);
}

static void bb_wq_start(struct bb_writer *bbw) {
	ev_io_start(blastbeat.loop, &bbw->writer);
}


int bb_wq_push(struct bb_session *bbs, char *buf, size_t len, int flags) {

	struct bb_connection *bbc = bbs->connection;
	if (!bbc) return -1;

	if (wq_push(&bbc->writer, buf, len, flags, bbs)) return -1;
	// an item has been pushed, start the ev_io
	bb_wq_start(&bbc->writer);
	return 0;
}

int bb_wq_dumb_push(struct bb_connection *bbc, char *buf, size_t len, int flags) {

        if (!bbc) return -1;

        if (wq_push(&bbc->writer, buf, len, flags, NULL)) return -1;
        // an item has been pushed, start the ev_io
	bb_wq_start(&bbc->writer);
        return 0;
}


int bb_wq_push_close(struct bb_session *bbs) {

	struct bb_connection *bbc = bbs->connection;
	if (!bbc) return -1;

	if (wq_push(&bbc->writer, NULL, 0, BB_WQ_CLOSE, bbs)) return -1;
	// an item has been pushed, start the ev_io
	bb_wq_start(&bbc->writer);
	return 0;
}

int bb_wq_push_eos(struct bb_session *bbs) {

	struct bb_connection *bbc = bbs->connection;
        if (!bbc) return -1;

	// persistent session cannot defer close
	if (bbs->persistent) return -1;

	if (wq_push(&bbc->writer, NULL, 0, BB_WQ_EOS, bbs)) return -1;
        // an item has been pushed, start the ev_io
	bb_wq_start(&bbc->writer);
        return 0;
}


int bb_wq_push_copy(struct bb_session *bbs, char *buf, size_t len, int flags) {

	struct bb_connection *bbc = bbs->connection;
	if (!bbc) return -1;

	char *new_buf = bb_alloc(len);
	if (!new_buf) {
		bb_error("unable to allocate memory for writequeue item: malloc()");
		return -1;
	}
	memcpy(new_buf, buf, len);

	if (wq_push(&bbc->writer, new_buf, len, flags, bbs)) return -1;
	// an item has been pushed, start the ev_io
	bb_wq_start(&bbc->writer);
	return 0;
}
