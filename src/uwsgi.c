#include "../blastbeat.h"

int add_uwsgi_item(struct bb_session *bbs, char *key, uint16_t keylen, char *val, uint16_t vallen, int hh) {

	if (bbs->request.uwsgi_pos + 2 + (hh*5) + keylen + 2 + vallen > 65536) {
		return -1;
	}

mem:
	if (bbs->request.uwsgi_pos + 2 + (hh*5) + keylen + 2 + vallen > bbs->request.uwsgi_len) {
		char *new_buf = bb_realloc(bbs->request.uwsgi_buf, bbs->request.uwsgi_len, 4096);
		if (!new_buf) {
			bb_error("relloac()");
			return -1;
		}
		bbs->request.uwsgi_buf = new_buf;
		bbs->request.uwsgi_len += 4096;
		if (bbs->request.uwsgi_pos + 2 + (hh*5) + keylen + 2 + vallen > bbs->request.uwsgi_len) {
			goto mem;
		}
	}


	char *ptr = bbs->request.uwsgi_buf + bbs->request.uwsgi_pos;
	
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

	bbs->request.uwsgi_pos += 2 + keylen + 2 + vallen;

	return 0;
	
}

int bb_uwsgi(struct bb_session *bbs) {

	// allocate the first chunk (leaving space for 4 bytes uwsgi header)
	bbs->request.uwsgi_buf = bb_alloc(4096);
	if (!bbs->request.uwsgi_buf) {
		bb_error("malloc()");
		return -1;
	}
	bbs->request.uwsgi_len = 4096;
	bbs->request.uwsgi_pos = 4;

	const char *r_method = http_method_str(bbs->request.parser.method);
	if (add_uwsgi_item(bbs, "REQUEST_METHOD", 14, (char *)r_method, strlen(r_method), 0)) return -1;
	if (add_uwsgi_item(bbs, "SCRIPT_NAME", 11, "", 0, 0)) return -1;

	char *query_string = memchr(bbs->request.headers[0].key, '?', bbs->request.headers[0].keylen);
	if (query_string) {
		if (add_uwsgi_item(bbs, "PATH_INFO", 9, bbs->request.headers[0].key, query_string-bbs->request.headers[0].key, 0)) return -1;
		if (add_uwsgi_item(bbs, "QUERY_STRING", 12, query_string+1, (bbs->request.headers[0].key+bbs->request.headers[0].keylen)-(query_string+1), 0)) return -1;
	}
	else {
		if (add_uwsgi_item(bbs, "PATH_INFO", 9, bbs->request.headers[0].key, bbs->request.headers[0].keylen, 0)) return -1;
		if (add_uwsgi_item(bbs, "QUERY_STRING", 12, "", 0, 0)) return -1;
	}

	struct bb_http_header *bbhh = bb_http_req_header(bbs, "Content-Type", 12);
	if (bbhh) {
		if (add_uwsgi_item(bbs, "CONTENT_TYPE", 12, bbhh->value, bbhh->vallen, 0))
			return -1;
	}
	bbhh = bb_http_req_header(bbs, "Content-Length", 14);
	if (bbhh) {
		if (add_uwsgi_item(bbs, "CONTENT_LENGTH", 14, bbhh->value, bbhh->vallen, 0))
			return -1;
	}

	char *port = strchr(bbs->vhost->name, ':');
	if (port) {
		if (add_uwsgi_item(bbs, "SERVER_NAME", 11, bbs->vhost->name, port-bbs->vhost->name, 0)) return -1;
		if (add_uwsgi_item(bbs, "SERVER_PORT", 11, port+1, (bbs->vhost->name + bbs->vhost->len) - (port+1), 0)) return -1;
	}
	else {
		if (add_uwsgi_item(bbs, "SERVER_NAME", 11, bbs->vhost->name, bbs->vhost->len, 0)) return -1;
		if (add_uwsgi_item(bbs, "SERVER_PORT", 11, "80", 2, 0)) return -1;
	}

	char proto[9];
	if (snprintf(proto, 9, "HTTP/%d.%d", bbs->request.parser.http_major, bbs->request.parser.http_minor) != 8) {
		return -1;
	}

	if (add_uwsgi_item(bbs, "SERVER_PROTOCOL", 15, proto, 8, 0))
		return -1;

	if (bbs->connection) {
		if (add_uwsgi_item(bbs, "REMOTE_ADDR", 11, bbs->connection->addr_str, bbs->connection->addr_str_len, 0))
			return -1;
		if (add_uwsgi_item(bbs, "REMOTE_PORT", 11, bbs->connection->addr_port, bbs->connection->addr_port_len, 0))
			return -1;
	}
	
	// add HTTP_ headers
	off_t i;	
	for(i=1;i<=bbs->request.header_pos;i++) {
                if (add_uwsgi_item(bbs, bbs->request.headers[i].key, bbs->request.headers[i].keylen, bbs->request.headers[i].value, bbs->request.headers[i].vallen, 1))
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
