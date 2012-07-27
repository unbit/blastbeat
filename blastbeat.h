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
#ifdef __APPLE__
#define MAC_OS_X_VERSION_MIN_REQUIRED MAC_OS_X_VERSION_10_4
#endif
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include "openssl/conf.h"
#include "openssl/ssl.h"
#include <openssl/err.h>
#include <sys/resource.h>
#include <pwd.h>
#include <grp.h>
#include <zlib.h>

#define MAX_HEADERS 100

#define MAX_CHUNK_STORAGE ((sizeof("18446744073709551616") * 2) + 3)
#ifndef ULLONG_MAX
# define ULLONG_MAX ((uint64_t) -1) /* 2^64-1 */
#endif
#define ntohll(y) (((uint64_t)ntohl(y)) << 32 | ntohl(y>>32))
#define htonll(y) (((uint64_t)htonl(y)) << 32 | htonl(y>>32))

#define BB_UUID_LEN	16


#define BLASTBEAT_TYPE_WEBSOCKET        1
#define BLASTBEAT_TYPE_SPDY		2

#define BLASTBEAT_DEALER_OFF		0
#define BLASTBEAT_DEALER_AVAILABLE	1

struct bb_virtualhost;
struct bb_session;

struct bb_str_list {
	char *name;
	size_t len;
	struct bb_str_list *next;
};

struct bb_dealer {
        char *identity;
	size_t len;
        time_t last_seen;
	int status;
	uint64_t load;
        struct bb_dealer *next;
};

struct bb_vhost_dealer {
	struct bb_dealer *dealer;
	struct bb_vhost_dealer *next;
};

struct bb_reader {
	ev_io reader;
	struct bb_connection *connection;
};

struct bb_acceptor;

struct bb_virtualhost {
	char *name;
	size_t len;
	struct bb_acceptor *acceptors;

	char *ssl_certificate;
	char *ssl_key;

	struct bb_vhost_dealer *dealers;
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
	struct bb_writer_item *next;
};

struct bb_writer {
	ev_io writer;
	struct bb_connection *connection;
	struct bb_writer_item *head;
	struct bb_writer_item *tail;
};

struct bb_connection {
        int fd;
        struct bb_reader reader;
	struct bb_acceptor *acceptor;
	// ssl session
	SSL *ssl;
	int spdy;

	z_stream spdy_z_in;
	z_stream spdy_z_out;

	int spdy_status;
	uint8_t spdy_control;
	uint16_t spdy_version;
	uint16_t spdy_type;
	uint8_t spdy_flags;
	uint32_t spdy_length;
	uint32_t spdy_stream_id;
	char spdy_header_buf[8];
	off_t spdy_header_pos;
	char *spdy_body_buf;
	off_t spdy_body_pos;

	// write queue
	struct bb_writer writer;

	struct bb_session *sessions_head;
	struct bb_session *sessions_tail;
		
};

struct bb_session {
	// this is the uuid key splitten in 2 64bit numbers
	uint64_t uuid_part1;
	uint64_t uuid_part2;

	// used by spdy
	uint32_t stream_id;

	// each session can run on a different dealer
	struct bb_dealer *dealer;
	// contains the virtualhost mapped to the session
	struct bb_virtualhost *vhost;

        int new_request;
        struct bb_session_request *requests_head;
        struct bb_session_request *requests_tail;

	// sanity check for 'retry' command
	uint64_t hops;

	// hash table management
	struct bb_session_entry *entry;
	struct bb_session *prev;
	struct bb_session *next;

	// connection link
	struct bb_connection *connection;
	struct bb_session *conn_prev;
        struct bb_session *conn_next;
};

struct bb_session_entry {
	struct bb_session *head;
	struct bb_session *tail;
};

union bb_addr {
	struct sockaddr in;
	struct sockaddr_in in4;
	struct sockaddr_in6 in6;
};

struct bb_acceptor {
	ev_io acceptor;
	char *name;
	int shared;
	union bb_addr addr;
	socklen_t addr_len;
	SSL_CTX *ctx;
	ssize_t (*read)(struct bb_connection *, char *, size_t);
	ssize_t (*write)(struct bb_connection *, char *, size_t);
	struct bb_virtualhost *vhosts;
	// this is a string list of acceptor->vhost mappings
	// required for building (later) the correct structure
	struct bb_str_list *mapped_vhosts;
	struct bb_acceptor *next;
};

struct blastbeat_server {
	struct bb_acceptor *acceptors;
	char *zmq;

	float ping_freq;
	int max_hops;

	char *uid;
	char *gid;

	void *router;
	int zmq_fd;
	struct ev_loop *loop;

	int max_fd;

	int ssl_initialized;
	char *ssl_certificate;
	char *ssl_key;
	int ssl_index;

	uint32_t sht_size;
	struct bb_session_entry *sht;

	struct bb_dealer *dealers;

	ev_io event_zmq;
	ev_timer pinger;

};


void bb_error(char *);
struct bb_http_header *bb_http_req_header(struct bb_session_request *, char *, size_t);
int bb_set_dealer(struct bb_session *, char *, size_t);
int bb_uwsgi(struct bb_session_request *);
struct bb_session *bb_sht_get(char *);

void bb_wq_callback(struct ev_loop *, struct ev_io *, int);
int bb_wq_push(struct bb_connection *, char *, size_t, int);
int bb_wq_push_copy(struct bb_connection *, char *, size_t, int);
int bb_wq_push_close(struct bb_connection *);

ssize_t bb_http_read(struct bb_connection *, char *, size_t);
ssize_t bb_http_write(struct bb_connection *, char *, size_t);
ssize_t bb_ssl_read(struct bb_connection *, char *, size_t);
ssize_t bb_ssl_write(struct bb_connection *, char *, size_t);

struct bb_session *bb_session_new(struct bb_connection *);
struct bb_session_request *bb_new_request(struct bb_session *);

void bb_connection_close(struct bb_connection *);
void bb_session_close(struct bb_session *);

void bb_raw_zmq_send_msg(char *, size_t, char *, size_t, char *, size_t, char *, size_t);
void bb_zmq_send_msg(char *, size_t, char *, size_t, char *, size_t, char *, size_t);
void bb_zmq_receiver(struct ev_loop *, struct ev_io *, int);

void bb_ssl_info_cb(SSL const *, int, int);

int add_uwsgi_item(struct bb_session_request *, char *, uint16_t, char *val, uint16_t, int);

void bb_socket_ssl(struct bb_acceptor *);
