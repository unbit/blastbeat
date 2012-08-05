#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

/*

	SPDY parser is different from the HTTP one
	The parsing is done at connection-level and each STREAM ID
	is mapped to a session

	When a full frame is received it is mapped to the relevant STREAM ID (if available)

*/

const char spdy_dictionary[] =
	"optionsgetheadpostputdeletetraceacceptaccept-charsetaccept-encodingaccept-"
	"languageauthorizationexpectfromhostif-modified-sinceif-matchif-none-matchi"
	"f-rangeif-unmodifiedsincemax-forwardsproxy-authorizationrangerefererteuser"
	"-agent10010120020120220320420520630030130230330430530630740040140240340440"
	"5406407408409410411412413414415416417500501502503504505accept-rangesageeta"
	"glocationproxy-authenticatepublicretry-afterservervarywarningwww-authentic"
	"ateallowcontent-basecontent-encodingcache-controlconnectiondatetrailertran"
	"sfer-encodingupgradeviawarningcontent-languagecontent-lengthcontent-locati"
	"oncontent-md5content-rangecontent-typeetagexpireslast-modifiedset-cookieMo"
	"ndayTuesdayWednesdayThursdayFridaySaturdaySundayJanFebMarAprMayJunJulAugSe"
	"pOctNovDecchunkedtext/htmlimage/pngimage/jpgimage/gifapplication/xmlapplic"
	"ation/xhtmltext/plainpublicmax-agecharset=iso-8859-1utf-8gzipdeflateHTTP/1"
	".1statusversionurl";

int bb_spdy_func(struct bb_connection *bbc, char *buf, size_t len) {
        // remember: in HTTP mode, only one session is allowed
        return bb_manage_spdy(bbc, buf, len);
}


void bb_ssl_info_cb(SSL const *ssl, int where, int ret) {
        if (where & SSL_CB_HANDSHAKE_DONE) {
#ifdef OPENSSL_NPN_UNSUPPORTED
                const unsigned char * proto = NULL;
                unsigned len = 0;
                SSL_get0_next_proto_negotiated(ssl, &proto, &len);
                if (len == 6 && !memcmp(proto, "spdy/2", 6)) {
                        struct bb_connection *bbc = SSL_get_ex_data(ssl, blastbeat.ssl_index);
                        // in the future it could be the version number instead of boolean
                        bbc->spdy = 1;
                        bbc->spdy_z_in.zalloc = Z_NULL;
                        bbc->spdy_z_in.zfree = Z_NULL;
                        bbc->spdy_z_in.opaque = Z_NULL;
                        if (inflateInit(&bbc->spdy_z_in) != Z_OK) {
				bb_connection_close(bbc);
				return;
			}
                        bbc->spdy_z_out.zalloc = Z_NULL;
                        bbc->spdy_z_out.zfree = Z_NULL;
                        bbc->spdy_z_out.opaque = Z_NULL;
                        if (deflateInit(&bbc->spdy_z_out, Z_DEFAULT_COMPRESSION) != Z_OK) {
				bb_connection_close(bbc);
				return;
			}
                        if (deflateSetDictionary(&bbc->spdy_z_out, (Bytef *) spdy_dictionary, sizeof(spdy_dictionary)) != Z_OK) {
				bb_connection_close(bbc);
				return;
			}
			// set the parser hook
			bbc->func = bb_spdy_func;
                }
#else
#warning OLD OpenSSL detected, SPDY support will not be enabled
#endif
                if (ssl->s3) {
                        ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
                }
        }
}

static int bb_spdy_pass_body(struct bb_connection *bbc) {
	bbc->spdy_stream_id = ntohl(bbc->spdy_stream_id);
	if (bbc->spdy_stream_id == 0) return -1;
	// find the stream
	struct bb_session *bbs = bbc->sessions_head;
	while(bbs) {
		if (bbs->stream_id == bbc->spdy_stream_id) {
			goto found;
		}
		bbs = bbs->next;
	}
	return -1;
found:
	if (!bbs->dealer) return -1;	
	bb_zmq_send_msg(bbs->dealer->identity, bbs->dealer->len, (char *) &bbs->uuid_part1, BB_UUID_LEN, "body", 4, bbc->spdy_body_buf, bbc->spdy_length);
	if (bbc->spdy_flags == 0x01) {
		bb_zmq_send_msg(bbs->dealer->identity, bbs->dealer->len, (char *) &bbs->uuid_part1, BB_UUID_LEN, "body", 4, "", 0);
	}
	return 0;

}

static int bb_spdy_uwsgi(struct bb_session *bbs, char *ptr, uint16_t hlen) {

        // allocate the first chunk (leaving space for 4 bytes uwsgi header)
        bbs->request.uwsgi_buf = malloc(4096);
        if (!bbs->request.uwsgi_buf) {
                bb_error("malloc()");
                return -1;
        }
        bbs->request.uwsgi_len = 4096;
        bbs->request.uwsgi_pos = 4;

	if (add_uwsgi_item(bbs, "SCRIPT_NAME", 11, "", 0, 0)) return -1;

	uint16_t i,klen,vlen;

	for(i=0;i<hlen;i++) {
                memcpy(&klen, ptr, 2);
                klen = ntohs(klen); ptr+=2;
		char *key = ptr;
                ptr += klen;

                memcpy(&vlen, ptr, 2);
                vlen = ntohs(vlen); ptr+=2;
		char *val = ptr;
                ptr += vlen;

		if (!bb_strcmp(key, klen, "method", 6)) {
			if (add_uwsgi_item(bbs, "REQUEST_METHOD", 14, val, vlen, 0)) return -1;
		}
		else if (!bb_strcmp(key, klen, "version", 7)) {
			if (add_uwsgi_item(bbs, "SERVER_PROTOCOL", 15, val, vlen, 0)) return -1;
		}
		else if (!bb_strcmp(key, klen, "host", 4)) {
			if (bb_set_dealer(bbs, val, vlen))
				return -1;
			if (add_uwsgi_item(bbs, "HTTP_HOST", 9, val, vlen, 0)) return -1;
		}
		else if (!bb_strcmp(key, klen, "content-type", 12)) {
			 if (add_uwsgi_item(bbs, "CONTENT_TYPE", 12, val, vlen, 0)) return -1;
		}
		else if (!bb_strcmp(key, klen, "content-length", 14)) {
			 if (add_uwsgi_item(bbs, "CONTENT_LENGTH", 14, val, vlen, 0)) return -1;
		}
		else if (!bb_strcmp(key, klen, "url", 3)) {
        		char *query_string = memchr(val, '?', vlen);
        		if (query_string) {
                		if (add_uwsgi_item(bbs, "PATH_INFO", 9, val, query_string-val, 0)) return -1;
                		if (add_uwsgi_item(bbs, "QUERY_STRING", 12, query_string+1, (val+vlen)-(query_string+1), 0)) return -1;
        		}
        		else {
                		if (add_uwsgi_item(bbs, "PATH_INFO", 9, val, vlen, 0)) return -1;
                		if (add_uwsgi_item(bbs, "QUERY_STRING", 12, "", 0, 0)) return -1;
        		}
		}
        	// add HTTP_ headers
		else {
			if (add_uwsgi_item(bbs, key, klen, val, vlen, 1)) return -1;
		}

        }

	char *port = NULL;
	if (bbs->dealer) {
		 port = strchr(bbs->vhost->name, ':');
	}

        if (bbs->dealer && port) {
               	if (add_uwsgi_item(bbs, "SERVER_NAME", 11, bbs->vhost->name, port-(bbs->vhost->name), 0)) return -1;
               	if (add_uwsgi_item(bbs, "SERVER_PORT", 11, port+1, (bbs->vhost->name + bbs->vhost->len) - (port+1), 0)) return -1;
        }
        else if (bbs->dealer) {
               	if (add_uwsgi_item(bbs, "SERVER_NAME", 11, bbs->vhost->name, bbs->vhost->len, 0)) return -1;
               	if (add_uwsgi_item(bbs, "SERVER_PORT", 11, "80", 2, 0)) return -1;
        }
	else {
		return -1;
	}

        // set uwsgi header
        uint16_t pktsize = bbs->request.uwsgi_pos;
        bbs->request.uwsgi_buf[0] = 0;
        bbs->request.uwsgi_buf[1] = (uint8_t) (pktsize & 0xff);
        bbs->request.uwsgi_buf[2] = (uint8_t) ((pktsize >> 8) & 0xff);
        bbs->request.uwsgi_buf[3] = 0;

        return 0;
}


static char *bb_spdy_deflate(z_stream *z, char *buf, size_t len, size_t *dlen) {

	// calculate the amount of bytes needed for output (+30 should be enough)
	// this memory will be freed by the writequeue engine
	char *dbuf = malloc(len+30);
	if (!dbuf) {
		bb_error("malloc()");
		return NULL;
	}
        z->avail_in = len;
        z->next_in = (Bytef *) buf;
        z->avail_out = len+30;
        z->next_out = (Bytef *) dbuf;

        if (deflate(z, Z_SYNC_FLUSH) != Z_OK) {
		return NULL;
	}
	*dlen = (char*) z->next_out - dbuf;

	return dbuf;
}

int bb_spdy_push_headers(struct bb_session *bbs) {
        int i;
        // calculate the destination buffer size
        // zzzzzzzzzzzzzzzzzzZZXXstatusXXyyyXXversionXXyyyyyyyy
        // transform all of the headers keys to lowercase
        size_t spdy_len = 52;
        for(i=1;i<=bbs->request.header_pos;i++) {
                spdy_len += 2 + bbs->request.headers[i].keylen + 2 + bbs->request.headers[i].vallen;
                size_t j;
                for(j=0;j<bbs->request.headers[i].keylen;j++) {
                        bbs->request.headers[i].key[j] = tolower((int) bbs->request.headers[i].key[j]);
                }
        }

        char *buf = malloc(spdy_len);
        if (!buf) {
                bb_error("malloc()");
                return -1;
        }

        // SYN_STREAM
        buf[0] = 0x80;
        buf[1] = 0x02;
        buf[2] = 0x00;
        buf[3] = 0x01;

        // flags UNIDIRECTIONAL
        buf[4] = 0x02;
        // 24 bit length (later)
        // ...

/*
        // stream_id
	bbs->connection->spdy_even_stream_id+=2;
	bbs->spdy_even_stream_id = bbsr->bbs->connection->spdy_even_stream_id;
        uint32_t stream_id = htonl(bbsr->spdy_even_stream_id);
        memcpy(buf+8, &stream_id, 4);

	// Associated-To-Stream-ID
        stream_id = htonl(bbsr->bbs->stream_id);
        memcpy(buf+12, &stream_id, 4);

        // unused
        buf[16] = 0x00;
        buf[17] = 0x00;

	// set the number of headers
        uint16_t hlen = htons(bbsr->header_pos+2);
        memcpy(buf+18, &hlen, 2);

        char *ptr = buf+20;
        uint16_t slen = htons(6);
        memcpy(ptr, &slen, 2); ptr+=2;
        memcpy(ptr, "status", 6); ptr+=6;
        slen = htons(3);
        memcpy(ptr, &slen, 2); ptr+=2;
        *ptr++ = (bbsr->parser.status_code/100) + '0';
        *ptr++ = ((bbsr->parser.status_code%100)/10) + '0';
        *ptr++ = ((bbsr->parser.status_code%100)%10) + '0';

        slen = htons(7);
        memcpy(ptr, &slen, 2); ptr+=2;
        memcpy(ptr, "version", 7); ptr+=7;

        slen = htons(8);
        char proto[9];
        if (snprintf(proto, 9, "HTTP/%d.%d", bbsr->parser.http_major, bbsr->parser.http_minor) != 8) {
                return -1;
        }
        memcpy(ptr, &slen, 2); ptr+=2;
        memcpy(ptr, proto, 8); ptr+=8;

        // generate spdy headers from respons headers
        for(i=1;i<=bbsr->header_pos;i++) {
                slen = htons(bbsr->headers[i].keylen);
                memcpy(ptr, &slen, 2); ptr += 2;
                memcpy(ptr, bbsr->headers[i].key, bbsr->headers[i].keylen);
                ptr += bbsr->headers[i].keylen;
                slen = htons(bbsr->headers[i].vallen);
                memcpy(ptr, &slen, 2); ptr += 2;
                memcpy(ptr, bbsr->headers[i].value, bbsr->headers[i].vallen);
                ptr += bbsr->headers[i].vallen;
        }

        size_t ch_len = 0;
        char *compresses_headers = bb_spdy_deflate(&bbsr->bbs->connection->spdy_z_out, buf+18, spdy_len-18, &ch_len);
        if (!compresses_headers) {
                return -1;
        }

        uint32_t l = htonl(10 + ch_len);
        void *ll = &l;
        memcpy(buf+5, ll+1, 3);

        if (bb_wq_push(bbsr->bbs->connection, buf, 18, 1)) {
                return -1;
        }

        if (bb_wq_push(bbsr->bbs->connection, compresses_headers, ch_len, 1)) {
                return -1;
        }
*/

        return 0;
}

static int bb_spdy_send_headers(struct bb_session *bbs, char *unused_buf, size_t len) {
	int i;
	// calculate the destination buffer size
	// zzzzzzzzzzzzzzZZXXstatusXXyyyXXversionXXyyyyyyyy
	// transform all of the headers keys to lowercase
	size_t spdy_len = 48;
	for(i=1;i<=bbs->response.header_pos;i++) {
		spdy_len += 2 + bbs->response.headers[i].keylen + 2 + bbs->response.headers[i].vallen;
		size_t j;
		for(j=0;j<bbs->response.headers[i].keylen;j++) {
			bbs->response.headers[i].key[j] = tolower((int) bbs->response.headers[i].key[j]);
		}
	}	

	char *buf = malloc(spdy_len);
	if (!buf) {
		bb_error("malloc()");
		return -1;
	}

	// SYN_REPLY
	buf[0] = 0x80;
	buf[1] = 0x02;
	buf[2] = 0x00;
	buf[3] = 0x02;

	// flags
	buf[4] = 0x00;
	// 24 bit length (later)
	// ...

	// stream_id
	uint32_t stream_id = htonl(bbs->stream_id);
	memcpy(buf+8, &stream_id, 4);

	// unused
	buf[12] = 0x00;
	buf[13] = 0x00;

	// set the number of headers
	uint16_t hlen = htons(bbs->response.header_pos+2);
	memcpy(buf+14, &hlen, 2);

	char *ptr = buf+16;
	uint16_t slen = htons(6);
	memcpy(ptr, &slen, 2); ptr+=2;
	memcpy(ptr, "status", 6); ptr+=6;
	slen = htons(3);
	memcpy(ptr, &slen, 2); ptr+=2;
	*ptr++ = (bbs->response.parser.status_code/100) + '0';
	*ptr++ = ((bbs->response.parser.status_code%100)/10) + '0';
	*ptr++ = ((bbs->response.parser.status_code%100)%10) + '0';

	slen = htons(7);
	memcpy(ptr, &slen, 2); ptr+=2;
	memcpy(ptr, "version", 7); ptr+=7;	

	slen = htons(8);
	char proto[9];
        if (snprintf(proto, 9, "HTTP/%d.%d", bbs->response.parser.http_major, bbs->response.parser.http_minor) != 8) {
                return -1;
        }
	memcpy(ptr, &slen, 2); ptr+=2;
	memcpy(ptr, proto, 8); ptr+=8;	

	// generate spdy headers from respons headers
	for(i=1;i<=bbs->response.header_pos;i++) {
		slen = htons(bbs->response.headers[i].keylen);
		memcpy(ptr, &slen, 2); ptr += 2;
		memcpy(ptr, bbs->response.headers[i].key, bbs->response.headers[i].keylen);
		ptr += bbs->response.headers[i].keylen;
		slen = htons(bbs->response.headers[i].vallen);
		memcpy(ptr, &slen, 2); ptr += 2;
		memcpy(ptr, bbs->response.headers[i].value, bbs->response.headers[i].vallen);
		ptr += bbs->response.headers[i].vallen;
	}

	size_t ch_len = 0;
	char *compresses_headers = bb_spdy_deflate(&bbs->connection->spdy_z_out, buf+14, spdy_len-14, &ch_len);
	if (!compresses_headers) {
		return -1;
	}

	uint32_t l = htonl(6 + ch_len);
	void *ll = &l;
	memcpy(buf+5, ll+1, 3);

	if (bb_wq_push(bbs, buf, 14, 1)) {
		return -1;
	}

	if (bb_wq_push(bbs, compresses_headers, ch_len, 1)) {
		return -1;
	}
	
	return 0;
}

static int bb_spdy_send_body(struct bb_session *bbs, char *buf, size_t len) {
	int ret = 0;
	uint32_t stream_id;
	char *spdy = malloc(len + 8);
	if (!spdy) {
		bb_error("malloc()");
		return -1;
	}
/*
	uint32_t stream_id = htonl(1);
	stream_id = (stream_id >> 1) & 0x7fffffff;
	memcpy(spdy, &stream_id, 4);
	if (bbs->response.type == BLASTBEAT_TYPE_SPDY_PUSH) {
		//stream_id = htonl(bbsr->spdy_even_stream_id);
		stream_id = 0;
	}
	else {
*/
		stream_id = htonl(bbs->stream_id);
//	}
	memcpy(spdy, &stream_id, 4);
	if (len > 0) {
		spdy[4] = 0;
	}
	else {
		// end of the stream
		spdy[4] = 0x01;
/*
		if (bbs->request.type == BLASTBEAT_TYPE_SPDY_PUSH) {
			ret = 0;
		}
		else {
*/
			//ret = 1;
//		}
	}

	uint32_t stream_length = htonl(len);
	void *sl = &stream_length;
	memcpy(spdy+5, sl+1, 3);
	memcpy(spdy + 8, buf, len);

	if (bb_wq_push(bbs, spdy, len+8, 1)) {
		return -1;
	}

	return ret;
}

static int bb_spdy_send_end(struct bb_session *bbs) {
	if (bb_spdy_send_body(bbs, "", 0)) return -1;
	return bb_wq_push_eos(bbs);
}

static int bb_spdy_inflate(struct bb_session *bbs, char *buf, size_t len) {

	struct bb_connection *bbc = bbs->connection;
	char *dbuf = NULL;
	size_t dbuf_len = 0;
	char zbuf[4096];
	off_t pos = 0;

	bbc->spdy_z_in.avail_in = len - 10;
	bbc->spdy_z_in.next_in = (Bytef *) buf + 10;

	while(bbc->spdy_z_in.avail_in > 0) {
		// calculate destination buffer
		dbuf_len+=4096;
		char *tmp_buf = realloc(dbuf, dbuf_len);
		if (!tmp_buf) {
			bb_error("malloc()");
			return -1;
		}
		dbuf = tmp_buf;

		bbc->spdy_z_in.avail_out = 4096;
		bbc->spdy_z_in.next_out = (Bytef *) zbuf;

		int ret = inflate(&bbc->spdy_z_in, Z_NO_FLUSH);
		if (ret == Z_NEED_DICT) {
			inflateSetDictionary(&bbc->spdy_z_in, (Bytef *) spdy_dictionary, sizeof(spdy_dictionary));
			ret = inflate(&bbc->spdy_z_in, Z_NO_FLUSH);
		}
		if (ret != Z_OK) return -1;
		size_t zlen = (char *)bbc->spdy_z_in.next_out-zbuf;	
		memcpy(dbuf+pos, zbuf, zlen);
		pos+=zlen;
	}


	uint16_t hlen = 0;
	memcpy(&hlen, dbuf, 2);
	hlen = ntohs(hlen);

	// generate a uwsgi packet from spdy headers
	// transform str sizes to little endian
	// TODO add a safety check on max buffer size
	if (bb_spdy_uwsgi(bbs, dbuf+2, hlen)) return -1;

	return 0;
}

static void bb_spdy_header(struct bb_connection *bbc) {
	bbc->spdy_control = (bbc->spdy_header_buf[0] >> 7) & 0x01;
	bbc->spdy_header_buf[0] = bbc->spdy_header_buf[0] & 0x7f;
	memcpy(&bbc->spdy_version, bbc->spdy_header_buf, 2);
	bbc->spdy_version = ntohs(bbc->spdy_version);
	bbc->spdy_flags = bbc->spdy_header_buf[4];
	void *slp = &bbc->spdy_length;
	memcpy(slp+1, bbc->spdy_header_buf + 5, 3);
	bbc->spdy_length = ntohl(bbc->spdy_length);
	if (bbc->spdy_control) {
		memcpy(&bbc->spdy_type, bbc->spdy_header_buf + 2, 2);
		bbc->spdy_type = ntohs(bbc->spdy_type);
	}
	else {
		memcpy(&bbc->spdy_stream_id, bbc->spdy_header_buf, 4);
	}
}

static int bb_manage_spdy_msg(struct bb_connection *bbc) {
	char *pong;
	switch(bbc->spdy_type) {
		// new STREAM
		case 0x01:
			bbc->spdy_body_buf[0] = bbc->spdy_body_buf[0] &0x7f;
			memcpy(&bbc->spdy_stream_id, bbc->spdy_body_buf, 4);
			bbc->spdy_stream_id = ntohl(bbc->spdy_stream_id);
			struct bb_session *bbs = bb_session_new(bbc);
			if (!bbs) return -1;
			// set the SPDY2 hooks
			bbs->send_headers = bb_spdy_send_headers;
			bbs->send_end = bb_spdy_send_end;
			bbs->send_body = bb_spdy_send_body;

			bbs->stream_id = bbc->spdy_stream_id;
			if (bb_spdy_inflate(bbs, bbc->spdy_body_buf, bbc->spdy_length)) {
				return -1;
			}
			// check for dealer as the host: header could be missing !!!
			if (!bbs->dealer) return -1;
			bb_zmq_send_msg(bbs->dealer->identity, bbs->dealer->len, (char *) &bbs->uuid_part1, BB_UUID_LEN, "uwsgi", 5, bbs->request.uwsgi_buf, bbs->request.uwsgi_pos);
			break;
		// RST
		case 0x03:
			memcpy(&bbc->spdy_stream_id, bbc->spdy_body_buf, 4);
			fprintf(stderr,"RESET THE STREAM %d\n", ntohl(bbc->spdy_stream_id));	
			break;
		// SETTINGS
		case 0x04:
			fprintf(stderr,"SETTINGS FLAGS %d\n", ntohl(bbc->spdy_flags));	
			break;
		// PING
		case 0x06:
			pong = malloc(8+4);
			if (!pong) {
				bb_error("pong malloc()");
				return -1;
			}
			memcpy(pong, "\x80\x02\x00\x06\x00\x00\x00\x04", 8);
			memcpy(pong + 8, bbc->spdy_body_buf, 4);
			if (bb_wq_dumb_push(bbc, pong, 12, 1)) {
				free(pong);
                		return -1;
        		}			
			break;
		default:
			fprintf(stderr,"UNKNOWN SPDY MESSAGE %d!!!\n", bbc->spdy_type);
			return -1;
	}
	return 0;
}

int bb_manage_spdy(struct bb_connection *bbc, char *buf, ssize_t len) {

	size_t remains = len;
	while(remains > 0) {
		switch(bbc->spdy_status) {
			// still waiting for 8 byte header
			case 0:
				// enough bytes ?
				if (remains >= (8-bbc->spdy_header_pos)) {
					memcpy(bbc->spdy_header_buf + bbc->spdy_header_pos, buf + (len- remains), (8-bbc->spdy_header_pos));
					remains -= (8-bbc->spdy_header_pos);
					// ready to receive the body
					bb_spdy_header(bbc);
					if (bbc->spdy_length > 0) {
						bbc->spdy_status = 1;
						if (bbc->spdy_body_buf) {
							free(bbc->spdy_body_buf);
						}
						bbc->spdy_body_buf = malloc(bbc->spdy_length);
						break;
					}
					return -1;
				}
				memcpy(bbc->spdy_header_buf + bbc->spdy_header_pos, buf + (len - remains), remains);
				bbc->spdy_header_pos += remains;
				return 0;
			case 1:
				if (remains >= (bbc->spdy_length - bbc->spdy_body_pos)) {
					memcpy(bbc->spdy_body_buf + bbc->spdy_body_pos , buf + (len - remains), (bbc->spdy_length - bbc->spdy_body_pos));
					remains -= (bbc->spdy_length - bbc->spdy_body_pos);
					if (bbc->spdy_type == 0) {
						if (bb_spdy_pass_body(bbc)) {
							return -1;
						}
					}
					else if (bb_manage_spdy_msg(bbc)) {
						return -1;
					}
					// reset SPDY parser
					free(bbc->spdy_body_buf);
					bbc->spdy_body_buf = NULL;
					bbc->spdy_body_pos = 0;
					bbc->spdy_length = 0;
					bbc->spdy_status = 0;
					bbc->spdy_header_pos = 0;
					bbc->spdy_body_pos = 0;
					bbc->spdy_stream_id = 0;
					bbc->spdy_type = 0;
					break;
				}
				memcpy(bbc->spdy_body_buf + bbc->spdy_body_pos , buf + (len - remains), remains);
				bbc->spdy_body_pos += remains;	
				return 0;
			default:
				return -1;
		}
	}
	return 0;
}
