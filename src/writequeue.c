#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

/*

	The BlastBeat write queue

	Non-blocking writes are pretty complex to manage
	This implementation uses a queue of buffers associated to an ev_io structure

	Whenever an item is put in the queue an ev_io writer will be start and it will try to
	write datas until it fails (returning EAGAIN or an incomplete write)

	The offset in each item is required for managing incomplete writes

	Bandwidth limiting

	limiting per-vhost bandwidth is vital for QoS
        the writequeue uses a token bucket algorithm

	->bandwidth -> is the bandiwdth limit (in bytes per second)
        ->bandwidth_bucket -> is initialized to 0 and incremented by ((->bandwidth*30)/1000) bytes every 30ms
	(30ms has been choosen as a good compromise between performance and load, but could be tunable)

	as soon as ->bandwidth_bucket == ->bandwidth the token-add hook is stopped (will be restarted as soon as it decrease)

	when the underlying socket is ready to WRITE data, N tokens are removed from the bucket (where N is the size of the packet,
	if the packet is bigger it will be split)

	if a WRITE event happens when the token is 0, we have a non conformant packet, the write event will be stopped, and will be restarted
	at the next token-add hook

*/
static int wq_push(struct bb_writer *bbw, char *buf, size_t len, int flags, struct bb_session *bbs) {

	
	// check writequeue_buffer
	if (bbw->len+len > blastbeat.writequeue_buffer) {
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

static void bb_throttle(struct bb_virtualhost *vhost, struct bb_connection *bbc) {
	// mark the vhost as throttled
	vhost->throttled = 1;
	// stop the writer
	ev_io_stop(blastbeat.loop, &bbc->writer.writer);
	bbc->throttle.vhost = vhost;
	bbc->throttle.connection = bbc;
	// wait for unthrottling
	ev_prepare_start(blastbeat.loop, &bbc->throttle.throttle);
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
			if (bandwidth > 0) {
				// full bucket detected throttle the connection
				if (bbwi->session->vhost->bandwidth_bucket == 0) {
					bb_throttle(bbwi->session->vhost, bbc);
					return;
				}

				// if packet is bigger than bucket size, split it
				if (bbw_len > bbwi->session->vhost->bandwidth_bucket) {
					bbw_len = bbwi->session->vhost->bandwidth_bucket;
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
			if (bbwi->session->vhost->bandwidth > 0) {
				bbwi->session->vhost->bandwidth_bucket -= wlen;
			}
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

void bb_connection_throttle_cb(struct ev_loop *loop, struct ev_prepare *w, int revents) {
	struct bb_connection_throttle *bbct = (struct bb_connection_throttle *) w;
	struct bb_virtualhost *vhost = bbct->vhost;
	struct bb_connection *bbc = bbct->connection;
	if (!vhost || !bbc) {
		fprintf(stderr,"BUG in throttle system !!!\n");
		return;
	}

	// no more throttled
	if (vhost->throttled == 0) {
		ev_prepare_stop(blastbeat.loop, w);
		// just for safety (could be useful in future implementations)
		bbct->vhost = NULL;
		bbct->connection = NULL;
		bb_wq_start(&bbc->writer);
	}
}

void bb_throttle_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
	struct bb_throttle *bbt = (struct bb_throttle *) w;
	struct bb_virtualhost *vhost = bbt->vhost;

	// bucket could be bigger if we decrease bandwidth from the dealer
	// (will be possibile soon ;)
	if (vhost->bandwidth_bucket >= vhost->bandwidth) return;

	uint64_t token = ((vhost->bandwidth*30)/1000);
	if (vhost->bandwidth_bucket + token > vhost->bandwidth) {
		vhost->bandwidth_bucket = vhost->bandwidth;
	}
	else {
		vhost->bandwidth_bucket += token;
	}
	// unthrottle
	vhost->throttled = 0;

}
