#include "../blastbeat.h"

// websocket request spawns from http one
int bb_websocket_func(struct bb_connection *bbc, char *buf, size_t len) {
	// remember: in HTTP mode, only one session is allowed
	return bb_manage_websocket(bbc->sessions_head, buf, len);
}


static char *base64(char *str, size_t *len) {
	char *buf = NULL;
        BIO *b64, *bmem;
        BUF_MEM *bptr;


        b64 = BIO_new(BIO_f_base64());
        bmem = BIO_new(BIO_s_mem());
        b64 = BIO_push(b64, bmem);
        BIO_write(b64, str, *len);
        if (BIO_flush(b64) <= 0) {
		goto clear;
	}
        BIO_get_mem_ptr(b64, &bptr);

        buf = malloc(bptr->length-1);
        memcpy(buf, bptr->data, bptr->length-1);
        *len = bptr->length-1;
clear:
        BIO_free_all(b64);
        return buf;
}

static void sha1(char *body, size_t len, char *dst) {
        SHA_CTX sha;
        SHA1_Init(&sha);
        SHA1_Update(&sha, body, len);
        SHA1_Update(&sha, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
        SHA1_Final((unsigned char *)dst, &sha);
}


int bb_send_websocket_handshake(struct bb_session *bbs) {
	char sha[20];
        struct bb_http_header *swk = bb_http_req_header(bbs, "sec-websocket-key", 17);
        if (!swk) return -1;
        //struct bb_http_header *origin = bb_http_req_header(bbs, "origin", 6);
        sha1(swk->value, swk->vallen, sha);
        size_t b_len = 20;
        char *b64 = base64(sha, &b_len);
	if (!b64) return -1;
        bbs->request.http_major = '0' + bbs->request.parser.http_major;
        bbs->request.http_minor = '0' + bbs->request.parser.http_minor;

	if (bb_wq_push(bbs, "HTTP/", 5, 0)) return -1;
	if (bb_wq_push(bbs, &bbs->request.http_major, 1, 0)) return -1;
	if (bb_wq_push(bbs, ".", 1, 0)) return -1;
	if (bb_wq_push(bbs, &bbs->request.http_minor, 1, 0)) return -1;
	if (bb_wq_push(bbs, " 101 WebSocket Protocol Handshake\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ", 98, 0)) return -1;
	if (bb_wq_push(bbs, b64, b_len, BB_WQ_FREE)) return -1;
	if (bb_wq_push(bbs, "\r\n\r\n", 4, 0)) return -1;

	return 0;
}

int bb_manage_websocket_header(struct bb_session *bbs, char byte1, char byte2) {
	char opcode = byte1 & 0xf;
	if (opcode == 0x01 || opcode == 0x02) {
        	bbs->request.websocket_message_has_mask = (byte2 >> 7) & 1;
        	bbs->request.websocket_message_size = byte2 & 0x7f;
		return 0;
	}
	if (opcode == 0x09) {
		if (bb_wq_push(bbs, "\xA\0", 2, 0)) return -1;
		return 0;
	}
	return -1;
}

void bb_websocket_pass(struct bb_session *bbs, char *buf, ssize_t len) {
	if (bbs->sio_connected) {
		bb_socketio_message(bbs, buf, len);
		return;
	}
        bb_zmq_send_msg(bbs->dealer->identity, bbs->dealer->len, (char *) &bbs->uuid_part1, BB_UUID_LEN, "websocket", 9, buf, len);
}

int bb_manage_websocket(struct bb_session *bbs, char *buf, ssize_t len) {


	bbs->request.websocket_message_queue = realloc(bbs->request.websocket_message_queue, bbs->request.websocket_message_queue_len + len);
	memcpy(bbs->request.websocket_message_queue + bbs->request.websocket_message_queue_len, buf, len);
	bbs->request.websocket_message_queue_len += len;

parser:
	switch(bbs->request.websocket_message_phase) {
		// new message get 2 byte header
		case 0:
			if (bbs->request.websocket_message_queue_len < 2) {
				return 0;
			}
			if (bb_manage_websocket_header(bbs, bbs->request.websocket_message_queue[0], bbs->request.websocket_message_queue[1])) {
				return -1;
			}
			if (bbs->request.websocket_message_has_mask) {
				bbs->request.websocket_message_phase = 1;
			}
			else {
				bbs->request.websocket_message_phase = 2;
			}
			bbs->request.websocket_message_queue_pos = 2;
			goto parser;
		// manage mask
		case 1:
			bbs->request.websocket_message_queue_pos += 4;
			bbs->request.websocket_message_phase = 2;
			goto parser;
		// manage size
		case 2:
			if (bbs->request.websocket_message_size == 126) {
				if (bbs->request.websocket_message_queue_len < 2 + (bbs->request.websocket_message_has_mask*4) + 2) {
					return 0;
				}
				uint16_t size = 0;
				memcpy(&size, bbs->request.websocket_message_queue + 2 + (bbs->request.websocket_message_has_mask*4), 2);
				bbs->request.websocket_message_size = ntohs(size);
				bbs->request.websocket_message_queue_pos += 2;
			}
			else if (bbs->request.websocket_message_size == 127) {
				if (bbs->request.websocket_message_queue_len < 2 + (bbs->request.websocket_message_has_mask*4) + 8) {
					return 0;
				}
				uint64_t size = 0;
				memcpy(&size, bbs->request.websocket_message_queue + 2 + (bbs->request.websocket_message_has_mask*4), 8);
				bbs->request.websocket_message_size = ntohll(size);
				bbs->request.websocket_message_queue_pos += 8;
			}
			bbs->request.websocket_message_phase = 3;
			goto parser;
		case 3:
			if (bbs->request.websocket_message_queue_len < bbs->request.websocket_message_queue_pos + bbs->request.websocket_message_size) {
                               return 0;
                       }
                       bbs->request.websocket_message_phase = 0;
                       if (bbs->request.websocket_message_has_mask) {
                               uint64_t i;
                               char *ptr = bbs->request.websocket_message_queue + bbs->request.websocket_message_queue_pos;
                               char *mask = bbs->request.websocket_message_queue + 2;
                               for(i=0;i<bbs->request.websocket_message_size;i++) {
                                       ptr[i] = ptr[i] ^ mask[i%4];
                               }
                       }
                       //fprintf(stderr, "message = %.*s\n", bbs->request.websocket_message_size, bbs->request.websocket_message_queue + bbs->request.websocket_message_queue_pos);
                       bb_websocket_pass(bbs, bbs->request.websocket_message_queue + bbs->request.websocket_message_queue_pos, bbs->request.websocket_message_size);
                       char *old_queue = bbs->request.websocket_message_queue;
                       uint64_t old_queue_len = bbs->request.websocket_message_queue_len;
                       bbs->request.websocket_message_queue = NULL;
                       bbs->request.websocket_message_queue_len = 0;
                       if (old_queue_len - (bbs->request.websocket_message_queue_pos + bbs->request.websocket_message_size) > 0) {
                       		bbs->request.websocket_message_queue = malloc(old_queue_len - (bbs->request.websocket_message_queue_pos + bbs->request.websocket_message_size));
				bbs->request.websocket_message_queue_len = old_queue_len - (bbs->request.websocket_message_queue_pos + bbs->request.websocket_message_size);
				memcpy(bbs->request.websocket_message_queue, old_queue + bbs->request.websocket_message_queue_pos + bbs->request.websocket_message_size, bbs->request.websocket_message_queue_len);
                       		free(old_queue);
				goto parser;
                       }
                       free(old_queue);
                       return 0;       
               default:
                       return -1;
       }
       return -1; 
 }



int bb_websocket_reply(struct bb_session *bbs, char *msg, size_t len) {
        char header[2];
        uint16_t len16;
        uint64_t len64;
	size_t pkt_len = len + 2;

        header[0] = 0x81;

        if (len < 126) {
                header[1] = len;
        }
        else if (len < (1 << 16)) {
                header[1] = 126;
                len16 = htons(len);
		pkt_len += 2;
        }
        else if (len < ((uint64_t)1 << 63)) {
                header[1] = 127;
                len64 = htonll((uint64_t)len);
		pkt_len += 8;
        }
	else {
		return -1;
	}

	char *buf = malloc(pkt_len);
	if (!buf) {
		bb_error("unable to allocate memory for websocket reply: malloc()");
		return -1;
	}

	memcpy(buf, header, 2);
	if (header[1] == 126) {
		memcpy(buf + 2, &len16, 2);
		memcpy(buf + 4, msg, len);
	}
	else if (header[1] == 127) {
		memcpy(buf + 2, &len64, 8);
		memcpy(buf + 10, msg, len);
	}
	else {
		memcpy(buf + 2, msg, len);
	}

	if (bb_wq_push(bbs, buf, pkt_len, BB_WQ_FREE)) return -1;
	return 0;
}

