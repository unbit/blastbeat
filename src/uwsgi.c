#include "../blastbeat.h"

static int add_uwsgi_item(struct bb_session_request *bbsr, char *key, uint16_t keylen, char *val, uint16_t vallen, int hh) {

	if (bbsr->uwsgi_pos + 2 + (hh*5) + keylen + 2 + vallen > 65536) {
		return -1;
	}

mem:
	if (bbsr->uwsgi_pos + 2 + (hh*5) + keylen + 2 + vallen > bbsr->uwsgi_len) {
		char *new_buf = realloc(bbsr->uwsgi_buf, bbsr->uwsgi_len + 4096);
		if (!new_buf) {
			bb_error("relloac()");
			return -1;
		}
		bbsr->uwsgi_buf = new_buf;
		bbsr->uwsgi_len += 4096;
		if (bbsr->uwsgi_pos + 2 + (hh*5) + keylen + 2 + vallen > bbsr->uwsgi_len) {
			goto mem;
		}
	}


	char *ptr = bbsr->uwsgi_buf + bbsr->uwsgi_pos;
	
	if (!hh) {
		*ptr++= (uint8_t) (keylen & 0xff);
		*ptr++= (uint8_t) ((keylen >> 8) & 0xff);
		memcpy(ptr, key, keylen); ptr+=keylen;
	}
	else {
		uint16_t i;
		for(i=0;i<keylen;i++) {
			key[i] = toupper((int) key[i]);
			if (key[i] == '-') {
				key[i] = '_';
			}
		}
		keylen += 5;
		*ptr++= (uint8_t) (keylen & 0xff);
		*ptr++= (uint8_t) ((keylen >> 8) & 0xff);
		memcpy(ptr, "HTTP_", 5);
		memcpy(ptr+5, key, keylen-5); ptr+=keylen;
	}

	*ptr++= (uint8_t) (vallen & 0xff);
	*ptr++= (uint8_t) ((vallen >> 8) & 0xff);
	memcpy(ptr, val, vallen); ptr+=vallen;

	bbsr->uwsgi_pos += 2 + keylen + 2 + vallen;

	return 0;
	
}

int bb_uwsgi(struct bb_session_request *bbsr) {

	// allocate the first chunk (leaving space for 4 bytes uwsgi header)
	bbsr->uwsgi_buf = malloc(4096);
	if (!bbsr->uwsgi_buf) {
		bb_error("malloc()");
		return -1;
	}
	bbsr->uwsgi_len = 4096;
	bbsr->uwsgi_pos = 4;

	const char *r_method = http_method_str(bbsr->parser.method);
	if (add_uwsgi_item(bbsr, "REQUEST_METHOD", 14, (char *)r_method, strlen(r_method), 0)) return -1;
	if (add_uwsgi_item(bbsr, "SCRIPT_NAME", 11, "", 0, 0)) return -1;

	char *query_string = memchr(bbsr->headers[0].key, '?', bbsr->headers[0].keylen);
	if (query_string) {
		if (add_uwsgi_item(bbsr, "PATH_INFO", 9, bbsr->headers[0].key, query_string-bbsr->headers[0].key, 0)) return -1;
		if (add_uwsgi_item(bbsr, "QUERY_STRING", 12, query_string+1, (bbsr->headers[0].key+bbsr->headers[0].keylen)-(query_string+1), 0)) return -1;
	}
	else {
		if (add_uwsgi_item(bbsr, "PATH_INFO", 9, bbsr->headers[0].key, bbsr->headers[0].keylen, 0)) return -1;
		if (add_uwsgi_item(bbsr, "QUERY_STRING", 12, "", 0, 0)) return -1;
	}

	struct bb_http_header *bbhh = bb_http_req_header(bbsr, "Content-Type", 12);
	if (bbhh) {
		if (add_uwsgi_item(bbsr, "CONTENT_TYPE", 12, bbhh->value, bbhh->vallen, 0))
			return -1;
	}
	bbhh = bb_http_req_header(bbsr, "Content-Length", 14);
	if (bbhh) {
		if (add_uwsgi_item(bbsr, "CONTENT_LENGTH", 14, bbhh->value, bbhh->vallen, 0))
			return -1;
	}

	char *port = strchr(bbsr->bbs->dealer->vhost->name, ':');
	if (port) {
		if (add_uwsgi_item(bbsr, "SERVER_NAME", 11, bbsr->bbs->dealer->vhost->name, port-bbsr->bbs->dealer->vhost->name, 0)) return -1;
		if (add_uwsgi_item(bbsr, "SERVER_PORT", 11, port+1, (bbsr->bbs->dealer->vhost->name + bbsr->bbs->dealer->vhost->len) - (port+1), 0)) return -1;
	}
	else {
		if (add_uwsgi_item(bbsr, "SERVER_NAME", 11, bbsr->bbs->dealer->vhost->name, bbsr->bbs->dealer->vhost->len, 0)) return -1;
		if (add_uwsgi_item(bbsr, "SERVER_PORT", 11, "80", 2, 0)) return -1;
	}

	char proto[9];
	if (snprintf(proto, 9, "HTTP/%d.%d", bbsr->parser.http_major, bbsr->parser.http_minor) != 8) {
		return -1;
	}

	if (add_uwsgi_item(bbsr, "SERVER_PROTOCOL", 15, proto, 8, 0))
		return -1;
	
	// add HTTP_ headers
	off_t i;	
	for(i=1;i<=bbsr->header_pos;i++) {
                if (add_uwsgi_item(bbsr, bbsr->headers[i].key, bbsr->headers[i].keylen, bbsr->headers[i].value, bbsr->headers[i].vallen, 1))
			return -1;
        }

	// set uwsgi header
	uint16_t pktsize = bbsr->uwsgi_pos;
	bbsr->uwsgi_buf[0] = 0;
	bbsr->uwsgi_buf[1] = (uint8_t) (pktsize & 0xff);
	bbsr->uwsgi_buf[2] = (uint8_t) ((pktsize >> 8) & 0xff);
	bbsr->uwsgi_buf[3] = 0;

	return 0;
}
