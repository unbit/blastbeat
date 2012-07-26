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
static int wq_push(struct bb_writer *bbw, char *buf, size_t len, int free_it, int close_it) {

	struct bb_writer_item *bbwi = malloc(sizeof(struct bb_writer_item));
	if (!bbwi) {
		bb_error("unable to allocate memory for a writequeue item: malloc()");
		return -1;
	}

	bbwi->buf = buf;
	bbwi->pos = 0;
	bbwi->len = len;
	bbwi->free_it = free_it;
	bbwi->close_it = close_it;
	bbwi->next = NULL;

	if (!bbw->head) {
		bbw->head = bbwi;
	}
	else {
		bbw->tail->next = bbwi;
	}

	bbw->tail = bbwi;
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
	if (head->free_it) {
		free(head->buf);
	}
	free(head);
}

void bb_wq_callback(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct bb_writer *bbw = (struct bb_writer *) w;
	struct bb_connection *bbc = bbw->connection;
	struct bb_writer_item *bbwi = bbw->head;
	while(bbwi) {
		if (bbwi->close_it) goto end;
		if (bbwi->len == 0) goto next;
		ssize_t wlen = bbc->acceptor->write(bbc, bbwi->buf+bbwi->pos, bbwi->len-bbwi->pos);
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
		if (wlen < bbwi->len-bbwi->pos) {
			bbwi->pos-=wlen;
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
}



int bb_wq_push(struct bb_connection *bbc, char *buf, size_t len, int free_it) {
	if (wq_push(&bbc->writer, buf, len, free_it, 0)) return -1;
	// an item has been pushed, start the ev_io
	ev_io_start(blastbeat.loop, &bbc->writer.writer);
	return 0;
}

int bb_wq_push_close(struct bb_connection *bbc) {

	if (wq_push(&bbc->writer, NULL, 0, 0, 1)) return -1;
	// an item has been pushed, start the ev_io
	ev_io_start(blastbeat.loop, &bbc->writer.writer);
	return 0;
}

int bb_wq_push_copy(struct bb_connection *bbc, char *buf, size_t len, int free_it) {

	char *new_buf = malloc(len);
	if (!new_buf) {
		bb_error("unable to allocate memory for writequeue item: malloc()");
		return -1;
	}
	memcpy(new_buf, buf, len);

	if (wq_push(&bbc->writer, new_buf, len, free_it, 0)) return -1;
	// an item has been pushed, start the ev_io
	ev_io_start(blastbeat.loop, &bbc->writer.writer);
	return 0;
}
