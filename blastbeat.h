/* BlastBeat */
#include <ev.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <arpa/inet.h>
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
#include <uuid/uuid.h>
#include <ctype.h>
#include <math.h>

#define MAX_HEADERS 100

#define MAX_CHUNK_STORAGE ((sizeof("18446744073709551616") * 2) + 3)
#define MAX_CONTENT_LENGTH (sizeof("18446744073709551616") + 5)
#ifndef ULLONG_MAX
# define ULLONG_MAX ((uint64_t) -1) /* 2^64-1 */
#endif
#define ntohll(y) (((uint64_t)ntohl(y)) << 32 | ntohl(y>>32))
#define htonll(y) (((uint64_t)htonl(y)) << 32 | htonl(y>>32))

#define BB_UUID_LEN	16

// flags for the writequeue
#define BB_WQ_FREE	(1 << 0)
#define BB_WQ_CLOSE	(1 << 1)
#define BB_WQ_EOS	(1 << 2)


#define BLASTBEAT_BUFSIZE	8192
#define BLASTBEAT_HOSTNAME_HTSIZE	65536

#define BLASTBEAT_DEALER_OFF		0
#define BLASTBEAT_DEALER_AVAILABLE	1

#define BLASTBEAT_MAX_GROUPNAME_LEN     64

#define BLASTBEAT_CACHE_FOUND	0
#define BLASTBEAT_CACHE_MISS	-1
#define BLASTBEAT_CACHE_ERROR	-2

struct bb_virtualhost;
struct bb_session;

// a dealer is a blackend node connecting to blastbeat
struct bb_dealer {
        char *identity;
	size_t len;
        time_t last_seen;
	int status;
	uint64_t load;
        struct bb_dealer *next;
};

// this is a dealer mapped to a virtualhost
struct bb_vhost_dealer {
	struct bb_dealer *dealer;
	struct bb_vhost_dealer *next;
};

// the ev_io reader structure
struct bb_reader {
	ev_io reader;
	struct bb_connection *connection;
};

struct bb_acceptor;

// groups subsystem (each virtualhost has its pool of groups)
struct bb_group_entry;
struct bb_group {
        char name[BLASTBEAT_MAX_GROUPNAME_LEN];
        size_t len;
        struct bb_virtualhost *vhost;
        struct bb_group_entry *entry;
        struct bb_group_session *sessions;
        struct bb_group *prev;
        struct bb_group *next;
};

struct bb_group_entry {
        struct bb_group *head;
        struct bb_group *tail;
};

struct bb_session_group {
	struct bb_group *group;
	struct bb_session_group *prev;
	struct bb_session_group *next;
};

struct bb_group_session {
	struct bb_session *session;
	struct bb_group_session *prev;
	struct bb_group_session *next;
};

struct bb_cache_item {
	ev_timer expires;
	char *key;
	size_t keylen;

	// useful for SPDY
	char protocol[8];
	char status[3];

        // the list of headers (must be freed after each request)
        struct bb_http_header *headers;
	// the number of headers
	off_t headers_count;
	// used by the header parser
        int last_was_value;
	// correctly parsed ?
	int valid;

	char *http_end_of_first_line;
	char *http_first_line;
	size_t http_first_line_len;
	
	char *body;
	size_t body_len;

	struct bb_cache_entry *entry;
	struct bb_cache_item *prev;
	struct bb_cache_item *next;
};

struct bb_cache_entry {
	struct bb_cache_item *head;
	struct bb_cache_item *tail;
};

// a blastbeat virtualhost
struct bb_virtualhost {
	char *name;
	size_t len;

	struct bb_vhost_acceptor *acceptors;
	struct bb_vhost_dealer *dealers;

	// the group hastable
	uint32_t ght_size;
	struct bb_group_entry *ght;

	// the cache store
	uint32_t cht_size;
	uint64_t cache_size;
	struct bb_cache_entry *cache;
	
	uint64_t max_sessions;
	uint64_t active_sessions;

	char *ssl_certificate;
	char *ssl_key;

	struct bb_virtualhost *next;
};


// structure defining an HTTP header
struct bb_http_header {
        char *key;
        size_t keylen;
        char *value;
        size_t vallen;
};

struct bb_session;
struct bb_session_entry;

struct bb_request {
	int initialized;
	// the joyent http_parser
	http_parser parser;
	// parsed headers
	off_t header_pos;
	// used by the header parser
	int last_was_value;
	// the list of headers (must be freed after each request)
	struct bb_http_header headers[MAX_HEADERS];
	char http_major;
	char http_minor;
	// websocket parser
	char *websocket_message_queue;
        uint64_t websocket_message_queue_len;
        uint64_t websocket_message_queue_pos;
        uint8_t websocket_message_phase;
        uint8_t websocket_message_has_mask;
	uint64_t websocket_message_size;
	// uwsgi translator
	int no_uwsgi;
	char *uwsgi_buf;
        size_t uwsgi_len;
        off_t uwsgi_pos;
	// socket.io
	int sio_post;
	char *sio_post_buf;
	size_t sio_post_buf_size;
};

struct bb_response {
	int initialized;
	// the joyent http_parser
        http_parser parser;
	off_t header_pos;
        // used by the header parser
        int last_was_value;
	// the list of headers (mus not allocate memory !!!)
	struct bb_http_header headers[MAX_HEADERS];
	uint64_t content_length;
	uint64_t written_bytes;
	int close;
};


// item for the write queue
struct bb_writer_item {
	char *buf;
	off_t pos;
	size_t len;
	int flags;
	// the session generating the item
	struct bb_session *session;
	struct bb_writer_item *next;
};

// the ev_io writer structure for the write queue
struct bb_writer {
	ev_io writer;
	struct bb_connection *connection;
	struct bb_writer_item *head;
	struct bb_writer_item *tail;
};

// a connection from a peer to blastbeat
struct bb_connection {
        int fd;
        struct bb_reader reader;
	struct bb_acceptor *acceptor;

	int (*func)(struct bb_connection *, char *, size_t);

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

	uint32_t spdy_even_stream_id;

	// write queue
	struct bb_writer writer;

	struct bb_session *sessions_head;
	struct bb_session *sessions_tail;
		
};

struct bb_socketio_message {
	char *buf;
	size_t len;
	struct bb_socketio_message *next;
};

// a blastbeat session (in HTTP it is mapped to a connection, in SPDY it is mapped to a stream)
struct bb_session {
	// destroy the session whenever this timer expires
	ev_timer death_timer;
	// this is the uuid key split in 2 64bit numbers
	uint64_t uuid_part1;
	uint64_t uuid_part2;

	// used by spdy
	uint32_t stream_id;
	// true if already correctly cleared (from the protocol pov)
	int fin;
	// the push queue
	char *push_queue;
	size_t push_queue_len;

	// each session can run on a different dealer
	struct bb_dealer *dealer;
	// contains the virtualhost mapped to the session
	struct bb_virtualhost *vhost;

	// used for monitoring inactivity
	time_t last_seen;

	// persistent sessions can be re-called (useful for socket.io in xhr-polling)
	int persistent;
	// stealth sessions never touch dealers
        int stealth;

	// mark socket.io connection status
	int sio_connected;
	// true if a socket.io poller is connected
	int sio_poller;
	// the queue of unsent messages
	struct bb_socketio_message *sio_queue;

	// the request parser structure (http, spdy, websocket, socket.io)
        struct bb_request request;

	// the response parser structure
        struct bb_response response;

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

	// subscribed group list
	struct bb_session_group *groups;

	// hooks
	int (*send_headers)(struct bb_session *, char *, size_t);
	int (*send_end)(struct bb_session *);
	int (*send_body)(struct bb_session *, char *, size_t);
	int (*send_cache_headers)(struct bb_session *, struct bb_cache_item *);
	int (*send_cache_body)(struct bb_session *, struct bb_cache_item *);
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

// an acceptor is a bound socket
struct bb_acceptor {
	ev_io acceptor;
	char *name;
	int shared;
	union bb_addr addr;
	socklen_t addr_len;
	SSL_CTX *ctx;
	ssize_t (*read)(struct bb_connection *, char *, size_t);
	ssize_t (*write)(struct bb_connection *, char *, size_t);
	// list of mapped virtualhosts
	struct bb_acceptor_vhost *vhosts;
	struct bb_acceptor *next;
};

// the list of virtualhosts mapped to an acceptor
struct bb_acceptor_vhost {
	struct bb_virtualhost *vhost;
	struct bb_acceptor_vhost *next;
};

// the list of acceptors mapped to a vhost
struct bb_vhost_acceptor {
	struct bb_acceptor *acceptor;
	struct bb_vhost_acceptor *next;
};

// hostnames (name -> vhost mappings)
struct bb_hostname {
	char *name;
	size_t len;
	struct bb_virtualhost *vhost;
	struct bb_hostname *next;
};

// the main server structure
struct blastbeat_server {
	struct bb_acceptor *acceptors;
	struct bb_virtualhost *vhosts;
	char *zmq;

	float ping_freq;
	int max_hops;

	char *uid;
	char *gid;

	uint64_t max_sessions;
	uint64_t active_sessions;

	void *router;
	int zmq_fd;
	struct ev_loop *loop;

	uint64_t max_fd;

	int ssl_initialized;
	char *ssl_certificate;
	char *ssl_key;
	int ssl_index;

	uint32_t sht_size;
	struct bb_session_entry *sht;

	struct bb_hostname *hnht[BLASTBEAT_HOSTNAME_HTSIZE];

	struct bb_dealer *dealers;

	ev_io event_zmq;
	ev_timer pinger;
	ev_timer stats;

};

void bb_ini_config(char *);

void bb_error(char *);
void bb_error_exit(char *);

struct bb_http_header *bb_http_req_header(struct bb_session *, char *, size_t);
int bb_set_dealer(struct bb_session *, char *, size_t);
int bb_uwsgi(struct bb_session *);
int bb_manage_chunk(struct bb_session *, char *, size_t);

struct bb_session *bb_sht_get(char *);
void bb_sht_remove(struct bb_session *);
void bb_sht_add(struct bb_session *);

void bb_wq_callback(struct ev_loop *, struct ev_io *, int);
int bb_wq_push(struct bb_session *, char *, size_t, int);
int bb_wq_push_copy(struct bb_session *, char *, size_t, int);
int bb_wq_push_close(struct bb_session *);
int bb_wq_push_eos(struct bb_session *);
int bb_wq_dumb_push(struct bb_connection *, char *, size_t, int);

ssize_t bb_http_read(struct bb_connection *, char *, size_t);
ssize_t bb_http_write(struct bb_connection *, char *, size_t);
ssize_t bb_ssl_read(struct bb_connection *, char *, size_t);
ssize_t bb_ssl_write(struct bb_connection *, char *, size_t);

struct bb_session *bb_session_new(struct bb_connection *);

void bb_connection_close(struct bb_connection *);
void bb_session_close(struct bb_session *);

void bb_raw_zmq_send_msg(char *, size_t, char *, size_t, char *, size_t, char *, size_t);
void bb_zmq_send_msg(char *, size_t, char *, size_t, char *, size_t, char *, size_t);
void bb_zmq_receiver(struct ev_loop *, struct ev_io *, int);

void bb_ssl_info_cb(SSL const *, int, int);

int add_uwsgi_item(struct bb_session *, char *, uint16_t, char *val, uint16_t, int);

void bb_socket_ssl(struct bb_acceptor *);

int bb_stricmp(char *, size_t, char *, size_t);
int bb_strcmp(char *, size_t, char *, size_t);
int bb_startswith(char *, size_t, char *, size_t);
size_t bb_str2num(char *, int);

int bb_manage_websocket(struct bb_session *, char *, ssize_t);
int bb_send_websocket_handshake(struct bb_session *);
int bb_websocket_reply(struct bb_session *, char *, size_t);

int bb_manage_spdy(struct bb_connection *, char *, ssize_t);
int bb_spdy_push_headers(struct bb_session *);

int bb_join_group(struct bb_session *, char *, size_t);
int bb_session_leave_group(struct bb_session *, struct bb_group *);
struct bb_group *bb_ght_get(struct bb_virtualhost *, char *, size_t);

void bb_initialize_request(struct bb_session *);
void bb_initialize_response(struct bb_session *);

int bb_manage_socketio(struct bb_session *);
int bb_socketio_push(struct bb_session *, char, char *, size_t);
int bb_socketio_send(struct bb_session *, char *, size_t);

int bb_http_func(struct bb_connection *, char *, size_t);
int bb_http_send_headers(struct bb_session *, char *, size_t);
int bb_http_send_end(struct bb_session *);
int bb_http_send_body(struct bb_session *, char *, size_t);

int bb_websocket_func(struct bb_connection *, char *, size_t);

struct bb_virtualhost *bb_vhost_get(char *, size_t);
void bb_vhost_push_acceptor(struct bb_virtualhost *, struct bb_acceptor *);

int bb_manage_cache(struct bb_session *, char *, size_t);
void bb_cache_store(struct bb_session *bbs, char *buf, size_t);

int null_cb(http_parser *);
int null_b_cb(http_parser *, const char *, size_t);

int bb_http_cache_send_headers(struct bb_session *, struct bb_cache_item *);
int bb_http_cache_send_body(struct bb_session *, struct bb_cache_item *);
