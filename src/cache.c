/*

	BlastBeat in-process caching subsystem

This is a simple key-value in-memory store allowing you to cache specific response

Each virtualhost as its cache with a limited memory (by default the cache is disabled)

To store an item in the cache just use the 'cache' message type. The message body
is a raw HTTP response prepended by a line reporting the key of the item, its expiration
time and an optional flag, set to 1 if this is an update (the options are space-splitted, in the future we could add more options):

An 'update' means to overwrite the old cache value, if it is already stored

/foo/bar?a=1&b=2 120 1\r\n
HTTP/1.1 200 OK\r\n
Content-Type: text/html\r\n
\r\n
<h1>Hello World</h1>

Once stored, if a client asks for

GET /foo/bar?a=1&b=2

BlastBeat will get it from the cache and will (eventually) translate it
to a suitable format (like translating it to SPDY).

An ev_io timer is generated for each cache item, when it expires the cache item is destroyed.

You can cache one HTTP-response per-value, so every 'cache' message will be parsed (before storing)
to (eventually) remove unneeded parts.

The size consumed by a cache item is computed as zmq_msg_size + sizeof(struct bb_cache_item)

A cache item stores headers and body on different memory areas. This is needed for simplyfing translations.

*/

#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

static int cache_message_complete(struct http_parser *parser) {
	struct bb_cache_item *bbci = (struct bb_cache_item *) parser->data;
	bbci->valid = 1;
	return 0;
}

static int cache_body(struct http_parser *parser, const char *buf, size_t len) {
	struct bb_cache_item *bbci = (struct bb_cache_item *) parser->data;
	char *tmp_buf = bb_realloc(bbci->body, bbci->body_len, len);
	if (!tmp_buf) {
		bb_error("unable to allocate cache body:");
		return -1;
	}
	if (!bbci->body && !bbci->http_end_of_first_line) {
		bbci->http_end_of_first_line = (char *) buf-4;
	}
	bbci->body = tmp_buf;
	memcpy(bbci->body+bbci->body_len, buf, len);
	bbci->body_len+=len;
	return 0;
}

static int cache_header_field_cb(http_parser *parser, const char *buf, size_t len) {
        struct bb_cache_item *bbci = (struct bb_cache_item *) parser->data;
        if (bbci->last_was_value) {
		struct bb_http_header *bbhh = bb_realloc(bbci->headers, sizeof(struct bb_http_header)*bbci->headers_count, sizeof(struct bb_http_header));
		if (!bbhh) {
			bb_error("unable to allocate memory for cache headers");
			return -1;
		}
		bbci->headers_len+=sizeof(struct bb_http_header);
		// is it the first header ?
		if (bbci->headers_count == 0) {
			bbci->http_end_of_first_line = (char *) buf-2;
		}
		bbci->headers = bbhh;
		int pos = bbci->headers_count;
                bbci->headers_count++;
                bbci->headers[pos].key = bb_alloc(len);
		if (!bbci->headers[pos].key) {
			bb_error("malloc()");
			return -1;
		}
		bbci->headers_len+=len;
                memcpy(bbci->headers[pos].key, buf, len);
		bbci->headers[pos].keylen = len;
        }
        else {
		int pos = bbci->headers_count-1;
		char *tmp_buf = bb_realloc(bbci->headers[pos].key, bbci->headers[pos].keylen, len);
		if (!tmp_buf) {
			bb_error("realloc()");
			return -1;
		}
		bbci->headers_len+= len;
		bbci->headers[pos].key = tmp_buf;
                memcpy(bbci->headers[pos].key + bbci->headers[pos].keylen, buf, len);
                bbci->headers[pos].keylen += len;
        }
        bbci->last_was_value = 0;
        return 0;
}

static int cache_header_value_cb(http_parser *parser, const char *buf, size_t len) {
	struct bb_cache_item *bbci = (struct bb_cache_item *) parser->data;
        int pos = bbci->headers_count-1;
        if (!bbci->last_was_value) {
                bbci->headers[pos].value = bb_alloc(len);
		if (!bbci->headers[pos].value) {
			bb_error("malloc()");
			return -1;
		}
		bbci->headers_len+=len;
                memcpy(bbci->headers[pos].value, buf, len);
                bbci->headers[pos].vallen = len;
        }
        else {
		char *tmp_buf = bb_realloc(bbci->headers[pos].value, bbci->headers[pos].vallen, len);	
		if (!tmp_buf) {
			bb_error("realloc()");
			return -1;
		}
		bbci->headers_len+=len;
		bbci->headers[pos].value = tmp_buf;
                memcpy(bbci->headers[pos].value + bbci->headers[pos].vallen, buf, len);
                bbci->headers[pos].vallen += len;
        }
        bbci->last_was_value = 1;
        return 0;
}


static http_parser_settings bb_http_cache_parser_settings = {
        .on_message_begin = null_cb,
        .on_message_complete = cache_message_complete,
        .on_headers_complete = null_cb,
        .on_header_field = cache_header_field_cb,
        .on_header_value = cache_header_value_cb,
        .on_url = null_b_cb,
        .on_body = cache_body,
};


static uint32_t djb2_hash_cache(char *key, size_t len, uint32_t mask) {

        uint32_t hash = 5381;
        size_t i;
        for(i=0;i<len;i++) {
                hash = hash * 33 + key[i];
        }

        return (hash % mask);

}

static int bb_cache_compare(struct bb_cache_item *bbci, char *name, size_t len, int frag) {
        if (bbci->keylen != len) return 0;
	if (bbci->frag != frag) return 0;
        return !memcmp(bbci->key, name, len);
}

// get a cache item
struct bb_cache_item *bb_cache_get(struct bb_virtualhost *vhost, char *name, size_t len, int frag) {

        uint32_t cht_pos = djb2_hash_cache(name, len, vhost->cht_size);
        struct bb_cache_entry *bbce = &vhost->cache[cht_pos];
        struct bb_cache_item *bbci = bbce->head;
        while(bbci) {
                if (bb_cache_compare(bbci, name, len, frag)) {
                        return bbci;
                }
                bbci = bbci->next;
        };
        return NULL;
}

static void bb_cache_clear(struct bb_cache_item *bbci) {
	size_t i;
	for(i=0;i<bbci->headers_count;i++) {
                if (bbci->headers[i].key)
                        bb_free(bbci->headers[i].key, bbci->headers[i].keylen);
                if (bbci->headers[i].value)
                        bb_free(bbci->headers[i].value, bbci->headers[i].vallen);
        }
        if (bbci->headers)
                bb_free(bbci->headers, sizeof(struct bb_http_header)*bbci->headers_count);
        if (bbci->body)
                bb_free(bbci->body, bbci->body_len);
        if (bbci->key)
                bb_free(bbci->key, bbci->keylen);
        if (bbci->http_first_line)
                bb_free(bbci->http_first_line, bbci->http_first_line_len);
        bb_free(bbci, sizeof(struct bb_cache_item));
}

static void bb_cache_destroy(struct bb_cache_item *bbci) {
	// stop the expires timer
	if (bbci->expires_num > 0) {
		ev_timer_stop(blastbeat.loop, &bbci->expires);
	}
        // get the ht entry
        struct bb_cache_entry *bbce = bbci->entry;
        // is it the first item ?
        if (bbci == bbce->head) {
                bbce->head = bbci->next;
        }
        // is it the last item ?
        if (bbci == bbce->tail) {
                bbce->tail = bbci->prev;
        }
        // prev entry ?
        if (bbci->prev) {
                bbci->prev->next = bbci->next;
        }
        //next entry ?
        if (bbci->next) {
                bbci->next->prev = bbci->prev;
        }

	if (bbci->len > bbci->vhost->allocated_cache) {
		fprintf(stderr,"BUG in cache memory accounting !!!\n");
	}

	bbci->vhost->allocated_cache -= bbci->len;
	blastbeat.cache_memory -= bbci->len;

	bb_cache_clear(bbci);
}

static void cache_expires_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
        struct bb_cache_item *bbci = (struct bb_cache_item *) w;
	bb_cache_destroy(bbci);
}


/*
here we run 2 parsers:

the first one will split options

key expires flags\r\n

if key is right and the body is present (an empty body, means: destroy the item)
the second one will run a http parser, if it is valid the cache_item is added to the hashtable

*/
void bb_cache_store(struct bb_session *bbs, char *buf, size_t len, int frag) {
	if (bbs->vhost->cache_size == 0) return;

	// check for space
	if (bbs->vhost->allocated_cache + (sizeof(struct bb_cache_item) + len) > bbs->vhost->cache_size) {
		fprintf(stderr,"!!! cache for virtualhost \"%.*s\" is full !!!\n", (int) bbs->vhost->len, bbs->vhost->name);
		return;
	}

	// 0->key 1->expires 2->flags 3->uninteresting 4->end
	int status = 0;
	uint32_t cht_pos;

	char *key = buf;
	char *expires = NULL;
	char *flags = NULL;
	size_t keylen = 0;
	size_t expires_len = 0;
	size_t flags_len = 0;

	size_t i;
	for(i=0;i<len;i++) {
		if (buf[i] == ' ') {
			if (status == 0) { keylen = i; status = 1; }
			else if (status == 1) { expires_len = i; status = 2;}
			else if (status == 2) { flags_len = i; status = 3;}
		}
		else if (buf[i] == '\n') {
			if (status == 4) break;
			if (status == 0) { keylen = i; status = 1; }
			else if (status == 1) { expires_len = i; status = 2;}
			else if (status == 2) { flags_len = i; status = 3;}
			break;
		}
		else if (buf[i] == '\r') {
			if (status == 4) break;
			if (status == 0) { keylen = i; status = 1; }
			else if (status == 1) { expires_len = i; status = 2;}
			else if (status == 2) { flags_len = i; status = 3;}
			status = 4;
		}
		else {
			if (status == 1 && !expires) { expires = buf+i; }
			else if (status == 2 && !flags) { flags = buf+i;}
		}
	}

	if (keylen == 0) return;

	// fix size
	if (expires_len > 0) {
		expires_len -= expires-buf;
	}
	if (flags_len > 0) {
		flags_len -= flags-buf;
	}

	uint64_t expires_num = bb_str2num(expires, expires_len);
	uint32_t flags_num = bb_str2num(flags, flags_len);

	struct bb_cache_item *already = bb_cache_get(bbs->vhost, key, keylen, frag);
	if (already) {
		// empty body, destroy the item
		if (len-(i+1) <= 0) {
			bb_cache_destroy(already);
			return ;
		}
		// by default ignore updates
		if (flags_num == 0) return;

		bb_cache_destroy(already);
	}

	char *http_buf = buf+(i+1);
	size_t http_buf_len = len-(i+1);

	struct bb_cache_item *bbci = bb_alloc(sizeof(struct bb_cache_item));
	if (!bbci) {
		bb_error("malloc()");
		return;
	}
	memset(bbci, 0, sizeof(struct bb_cache_item));

	if (frag) {
		bbci->body = bb_alloc(http_buf_len);
		if (!bbci->body) {
			bb_error("malloc()");
			goto clear;
		}		
		memcpy(bbci->body, http_buf, http_buf_len);
		bbci->body_len = http_buf_len;
		goto store;
	}

	http_parser parser;
	http_parser_init(&parser, HTTP_RESPONSE);

	bbci->last_was_value = 1;
	parser.data = bbci;

	int res = http_parser_execute(&parser, &bb_http_cache_parser_settings, http_buf, http_buf_len);
	if (!bbci->valid && res != http_buf_len) goto clear;

	bbci->status[0] = (parser.status_code/100) + '0';
        bbci->status[1] = ((parser.status_code%100)/10) + '0';
        bbci->status[2] = ((parser.status_code%100)%10) + '0';

	memcpy(bbci->protocol, http_buf, 8);

	bbci->http_first_line_len = bbci->http_end_of_first_line-http_buf;
	bbci->http_first_line = bb_alloc(bbci->http_first_line_len);
	if (!bbci->http_first_line) {
		bb_error("malloc()");
		goto clear;
	}
	memcpy(bbci->http_first_line, http_buf, bbci->http_first_line_len);

store:
        // get the hash
        cht_pos = djb2_hash_cache(key, keylen, bbs->vhost->cht_size);
        // get the ht entry
        struct bb_cache_entry *bbce = &bbs->vhost->cache[cht_pos];

        bbci->key = bb_alloc(keylen);
	if (!bbci->key) {
		bb_error("malloc()");
		goto clear;
	}

	memcpy(bbci->key, key, keylen);
        bbci->keylen = keylen;
	bbci->frag = frag;
	bbci->entry = bbce;
        bbci->next = NULL;
	bbci->len = sizeof(struct bb_cache_item) + bbci->body_len + bbci->http_first_line_len + keylen + bbci->headers_len;
	bbci->expires_num = expires_num;
	bbci->vhost = bbs->vhost;

        // append cache item to entry
        if (!bbce->head) {
                bbci->prev = NULL;
                bbce->head = bbci;
        }
        else {
                bbci->prev = bbce->tail;
                bbce->tail->next = bbci;
        }
        bbce->tail = bbci;

	if (expires_num > 0) {
        	ev_timer_init(&bbci->expires, cache_expires_cb, expires_num, 0.0);
		ev_timer_start(blastbeat.loop, &bbci->expires);
	}

	bbs->vhost->allocated_cache += bbci->len;
	blastbeat.cache_memory += bbci->len;
	
	return;

clear:
	bb_cache_clear(bbci);
}



int bb_manage_cache(struct bb_session *bbs, char *key, size_t keylen) {

	struct bb_cache_item *bbci = bb_cache_get(bbs->vhost, key, keylen, 0);
	if (!bbci) return BLASTBEAT_CACHE_MISS;

	// first send headers
	if (bbs->send_cache_headers(bbs, bbci)) {
		return BLASTBEAT_CACHE_ERROR;
	}

	// first send headers
	if (bbs->send_cache_body(bbs, bbci)) {
		return BLASTBEAT_CACHE_ERROR;
	}

	return BLASTBEAT_CACHE_FOUND;
}
