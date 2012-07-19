#include "../blastbeat.h"

static char *base64(char *str, size_t *len) {
        BIO *b64, *bmem;
        BUF_MEM *bptr;


        b64 = BIO_new(BIO_f_base64());
        bmem = BIO_new(BIO_s_mem());
        b64 = BIO_push(b64, bmem);
        BIO_write(b64, str, *len);
        BIO_flush(b64);
        BIO_get_mem_ptr(b64, &bptr);

        char *buf = malloc(bptr->length-1);
        memcpy(buf, bptr->data, bptr->length-1);
        *len = bptr->length-1;
        BIO_free_all(b64);


        return buf;
}

static void sha1(char *body, size_t len, char *dst) {
        SHA_CTX sha;
        SHA1_Init(&sha);
        SHA1_Update(&sha, body, len);
        SHA1_Update(&sha, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
        SHA1_Final(dst, &sha);
}


int bb_send_websocket_handshake(struct bb_session_request *bbsr) {
        char sha[20];
        struct bb_http_header *swk = bb_http_req_header(bbsr, "sec-websocket-key", 17);
        if (!swk) return -1;
        struct bb_http_header *origin = bb_http_req_header(bbsr, "origin", 6);
        sha1(swk->value, swk->vallen, sha);
        size_t b_len = 20;
        char *b64 = base64(sha, &b_len);
        char http_major = '0' + bbsr->parser.http_major;
        char http_minor = '0' + bbsr->parser.http_minor;

        struct iovec iov[8];

        iov[0].iov_base = "HTTP/";
        iov[0].iov_len = 5;

        iov[1].iov_base = &http_major;
        iov[1].iov_len = 1;

        iov[2].iov_base = ".";
        iov[2].iov_len = 1;

        iov[3].iov_base = &http_minor;
        iov[3].iov_len = 1;

        iov[4].iov_base = " 101 WebSocket Protocol Handshake\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n";
        iov[4].iov_len = 76;

        iov[5].iov_base = "Sec-WebSocket-Accept: ";
        iov[5].iov_len = 22;

        iov[6].iov_base = b64;
        iov[6].iov_len = b_len;

        iov[7].iov_base = "\r\n\r\n";
        iov[7].iov_len = 4;

        for(;;) {
                ssize_t wlen = writev(bbsr->bbs->fd, iov, 8);
                if (wlen < 0) {
                        if (errno == EAGAIN) continue;
                        bb_error("writev()");
                }
                break;
        }

}

int bb_manage_websocket_header(struct bb_session_request *bbsr, char byte1, char byte2) {
        bbsr->websocket_message_has_mask = (byte2 >> 7) & 1;
        bbsr->websocket_message_size = byte2 & 0x7f;
}

int bb_websocket_pass(struct bb_session_request *bbsr, char *buf, ssize_t len) {
        bb_zmq_send_msg(bbsr->bbs->dealer->identity, bbsr->bbs->dealer->len, (char *) &bbsr->bbs->fd, 4, "websocket", 9, buf, len);
}

int bb_manage_websocket(struct bb_session_request *bbsr, char *buf, ssize_t len) {

	bbsr->websocket_message_queue = realloc(bbsr->websocket_message_queue, bbsr->websocket_message_queue_len + len);
	memcpy(bbsr->websocket_message_queue + bbsr->websocket_message_queue_len, buf, len);
	bbsr->websocket_message_queue_len += len;

parser:
	switch(bbsr->websocket_message_phase) {
		// new message get 2 byte header
		case 0:
			if (bbsr->websocket_message_queue_len < 2) {
				return 0;
			}
			bb_manage_websocket_header(bbsr, bbsr->websocket_message_queue[0], bbsr->websocket_message_queue[1]);
			if (bbsr->websocket_message_has_mask) {
				bbsr->websocket_message_phase = 1;
			}
			else {
				bbsr->websocket_message_phase = 2;
			}
			bbsr->websocket_message_queue_pos = 2;
			goto parser;
		// manage mask
		case 1:
			bbsr->websocket_message_queue_pos += 4;
			bbsr->websocket_message_phase = 2;
			goto parser;
		// manage size
		case 2:
			if (bbsr->websocket_message_size == 126) {
				if (bbsr->websocket_message_queue_len < 2 + (bbsr->websocket_message_has_mask*4) + 2) {
					return 0;
				}
				uint16_t size = 0;
				memcpy(&size, bbsr->websocket_message_queue + 2 + (bbsr->websocket_message_has_mask*4), 2);
				bbsr->websocket_message_size = ntohs(size);
				bbsr->websocket_message_queue_pos += 2;
			}
			else if (bbsr->websocket_message_size == 127) {
				if (bbsr->websocket_message_queue_len < 2 + (bbsr->websocket_message_has_mask*4) + 8) {
					return 0;
				}
				uint64_t size = 0;
				memcpy(&size, bbsr->websocket_message_queue + 2 + (bbsr->websocket_message_has_mask*4), 8);
				bbsr->websocket_message_size = ntohll(size);
				bbsr->websocket_message_queue_pos += 8;
			}
			bbsr->websocket_message_phase = 3;
			goto parser;
		case 3:
			if (bbsr->websocket_message_queue_len < bbsr->websocket_message_queue_pos + bbsr->websocket_message_size) {
                               return 0;
                       }
                       bbsr->websocket_message_phase = 0;
                       if (bbsr->websocket_message_has_mask) {
                               uint64_t i;
                               char *ptr = bbsr->websocket_message_queue + bbsr->websocket_message_queue_pos;
                               char *mask = bbsr->websocket_message_queue + 2;
                               for(i=0;i<bbsr->websocket_message_size;i++) {
                                       ptr[i] = ptr[i] ^ mask[i%4];
                               }
                       }
                       //printf("message = %.*s\n", bbsr->websocket_message_size, bbsr->websocket_message_queue + bbsr->websocket_message_queue_pos);
                       bb_websocket_pass(bbsr, bbsr->websocket_message_queue + bbsr->websocket_message_queue_pos, bbsr->websocket_message_size);
                       char *old_queue = bbsr->websocket_message_queue;
                       uint64_t old_queue_len = bbsr->websocket_message_queue_len;
                       bbsr->websocket_message_queue = NULL;
                       bbsr->websocket_message_queue_len = 0;
                       if (old_queue_len - (bbsr->websocket_message_queue_pos + bbsr->websocket_message_size) > 0) {
                               bbsr->websocket_message_queue = malloc(old_queue_len - (bbsr->websocket_message_queue_pos + bbsr->websocket_message_size));
                               bbsr->websocket_message_queue_len = old_queue_len - (bbsr->websocket_message_queue_pos + bbsr->websocket_message_size);
                       }
                       free(old_queue);
                       return 0;       
               default:
                       return -1;
       }
       return 0; 
 }



int bb_websocket_reply(struct bb_session_request *bbsr, char *buf, size_t len) {
        char header[2];
        uint16_t len16;
        uint64_t len64;
        struct iovec iov[3];
        header[0] = 0x81;

        if (len < 126) {
                header[1] = len;
                iov[1].iov_base = "";
                iov[1].iov_len = 0;
        }
        else if (len < (1 << 16)) {
                header[1] = 126;
                len16 = htons(len);
                iov[1].iov_base = &len16;
                iov[1].iov_len = 2;
        }
        else if (len < ((uint64_t)1 << 63)) {
                header[1] = 127;
                len64 = htonll(len);
                iov[1].iov_base = &len64;
                iov[1].iov_len = 8;
        }

        iov[0].iov_base = header;
        iov[0].iov_len = 2;

        iov[2].iov_base = buf;
        iov[2].iov_len = len;

        ssize_t wlen = writev(bbsr->bbs->fd, iov, 3);
        // MANAGE THAT
}

