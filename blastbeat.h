#include <ev.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "http-parser/http_parser.h"
#include <zmq.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <sys/resource.h>
#include <pwd.h>
#include <grp.h>

#define MAX_HEADERS 100

#define MAX_CHUNK_STORAGE ((sizeof("18446744073709551616") * 2) + 3)
#ifndef ULLONG_MAX
# define ULLONG_MAX ((uint64_t) -1) /* 2^64-1 */
#endif
#define ntohll(y) (((uint64_t)ntohl(y)) << 32 | ntohl(y>>32))
#define htonll(y) (((uint64_t)htonl(y)) << 32 | htonl(y>>32))

#define BB_UUID_LEN	16


#define BLASTBEAT_TYPE_WEBSOCKET        1

struct bb_virtualhost;
struct bb_session;

struct bb_dealer {
        char *identity;
	size_t len;
        char *identify_prefix;
        time_t last_pong;
	struct bb_virtualhost *vhost;
        struct bb_dealer *next;
};

struct bb_pinger {
	ev_timer pinger;
	struct bb_virtualhost *vhost;
};

struct bb_reader {
	ev_io reader;
	struct bb_session *session;
};

struct bb_virtualhost {
	char *name;
	size_t len;
	struct bb_pinger pinger;
	struct bb_dealer *dealers;
	struct bb_virtualhost *next;
};

struct bb_http_header {
        char *key;
        size_t keylen;
        char *value;
        size_t vallen;
};

struct bb_session;
struct bb_session_entry;

struct bb_session_request {
        struct bb_session *bbs;
        http_parser parser;
        off_t header_pos;
        int last_was_value;
        int close;
        int type;
	char http_major;
	char http_minor;
        uint64_t content_length;
        uint64_t written_bytes;
	char *uwsgi_buf;
	size_t uwsgi_len;
	off_t uwsgi_pos;
        char *websocket_message_queue;
        uint64_t websocket_message_queue_len;
        uint64_t websocket_message_queue_pos;
        uint8_t websocket_message_phase;
        uint8_t websocket_message_has_mask;
        //char websocket_message_mask[4];
        uint64_t websocket_message_size;
        struct bb_http_header headers[MAX_HEADERS];
        struct bb_session_request *next;
};

struct bb_writer_item {
	char *buf;
	off_t pos;
	size_t len;
	int free_it;
	int close_it;
	struct bb_writer_item *prev;
	struct bb_writer_item *next;
};

struct bb_writer {
	ev_io writer;
	struct bb_session *session;
	struct bb_writer_item *head;
	struct bb_writer_item *tail;
};

struct bb_session {
	// this is the uuid key splitten in 2 64bit numbers
	uint64_t uuid_part1;
	uint64_t uuid_part2;
        int fd;
        struct bb_reader reader;
        int new_request;
	struct bb_dealer *dealer;
        struct bb_session_request *requests_head;
        struct bb_session_request *requests_tail;

	// write queue
	struct bb_writer writer;

	// hash table management
	struct bb_session_entry *entry;
	struct bb_session *prev;
	struct bb_session *next;
};

struct bb_session_entry {
	struct bb_session *head;
	struct bb_session *tail;
};

struct blastbeat_server {
	char *addr;
	unsigned short port;
	char *zmq;

	float ping_freq;

	char *uid;
	char *gid;

	void *router;
	int zmq_fd;
	struct ev_loop *loop;

	int max_fd;

	uint32_t sht_size;
	struct bb_session_entry *sht;

	ev_io event_accept;
	ev_io event_zmq;

	struct bb_virtualhost *vhosts;
};


void bb_error(char *);
struct bb_http_header *bb_http_req_header(struct bb_session_request *, char *, size_t);
struct bb_dealer *bb_get_dealer(char *, size_t);
int bb_uwsgi(struct bb_session_request *);
struct bb_session *bb_sht_get(char *);
void bb_wq_callback(struct ev_loop *, struct ev_io *, int);
int bb_wq_push(struct bb_session *, char *, size_t, int);
