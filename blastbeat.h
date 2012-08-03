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
#ifndef ULLONG_MAX
# define ULLONG_MAX ((uint64_t) -1) /* 2^64-1 */
#endif
#define ntohll(y) (((uint64_t)ntohl(y)) << 32 | ntohl(y>>32))
#define htonll(y) (((uint64_t)htonl(y)) << 32 | htonl(y>>32))

#define BB_UUID_LEN	16


#define BLASTBEAT_TYPE_WEBSOCKET        1
#define BLASTBEAT_TYPE_SPDY		2
#define BLASTBEAT_TYPE_SPDY_PUSH	3

#define BLASTBEAT_DEALER_OFF		0
#define BLASTBEAT_DEALER_AVAILABLE	1

#define BLASTBEAT_MAX_GROUPNAME_LEN     64

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


// a blastbeat virtualhost
struct bb_virtualhost {
	char *name;
	size_t len;

	struct bb_vhost_acceptor *acceptors;
	struct bb_vhost_dealer *dealers;

	// the group hastable
	uint32_t ght_size;
	struct bb_group_entry *ght;

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

// each session can generate a specific request
struct bb_session_request {
        struct bb_session *bbs;
        http_parser parser;
        off_t header_pos;
        int last_was_value;
        int close;
        int type;
	int do_not_free;
	// do not generate a uwsgi message
	int no_uwsgi;
	// is it a socket.io POST ?
	int sio_post;
	char *sio_post_buf;
	size_t sio_post_buf_size;
	// ptr to the persistent socket.io session
        struct bb_session *sio_bbs;
	char http_major;
	char http_minor;
        uint64_t content_length;
        uint64_t written_bytes;
	char *uwsgi_buf;
	size_t uwsgi_len;
	off_t uwsgi_pos;
	uint32_t spdy_even_stream_id;
        char *websocket_message_queue;
        uint64_t websocket_message_queue_len;
        uint64_t websocket_message_queue_pos;
        uint8_t websocket_message_phase;
        uint8_t websocket_message_has_mask;
        //char websocket_message_mask[4];
        uint64_t websocket_message_size;
        struct bb_http_header headers[MAX_HEADERS];
        struct bb_session_request *prev;
        struct bb_session_request *next;
};


// item for the write queue
struct bb_writer_item {
	char *buf;
	off_t pos;
	size_t len;
	int free_it;
	int close_it;
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

// a blastbeat session (in HTTP it is mapped to a connection, in SPDY it is mapped to a stream)
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

	// persistent sessions can be re-called (useful for socket.io in xhr-polling)
	int persistent;
	// quiet death is for current session recovering a new one
        int quiet_death;

	// mark socket.io connection status
	int sio_connected;
	// true if a socket.io poller is connected
	int sio_poller;
	ev_timer sio_timer;

	// if set, generate a new session_request structure
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

	// subscribed group list
	struct bb_session_group *groups;
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


// the main server structure
struct blastbeat_server {
	struct bb_acceptor *acceptors;
	struct bb_virtualhost *vhosts;
	char *zmq;

	float ping_freq;
	int max_hops;

	char *uid;
	char *gid;

	uint64_t active_sessions;

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
	ev_timer stats;

};

void bb_ini_config(char *);

void bb_error(char *);
void bb_error_exit(char *);

struct bb_http_header *bb_http_req_header(struct bb_session_request *, char *, size_t);
int bb_set_dealer(struct bb_session *, char *, size_t);
int bb_uwsgi(struct bb_session_request *);
int bb_manage_chunk(struct bb_session_request *, char *, size_t);

struct bb_session *bb_sht_get(char *);
void bb_sht_remove(struct bb_session *);
void bb_sht_add(struct bb_session *);

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

int bb_stricmp(char *, size_t, char *, size_t);
int bb_strcmp(char *, size_t, char *, size_t);
int bb_startswith(char *, size_t, char *, size_t);

int bb_manage_websocket(struct bb_session_request *, char *, ssize_t);
int bb_send_websocket_handshake(struct bb_session_request *);
int bb_websocket_reply(struct bb_session_request *, char *, size_t);

int bb_manage_spdy(struct bb_connection *, char *, ssize_t);
int bb_spdy_send_body(struct bb_session_request *, char *, size_t);
int bb_spdy_send_headers(struct bb_session_request *);
int bb_spdy_push_headers(struct bb_session_request *);

int bb_join_group(struct bb_session *, char *, size_t);
int bb_session_leave_group(struct bb_session *, struct bb_group *);
struct bb_group *bb_ght_get(struct bb_virtualhost *, char *, size_t);

int bb_manage_socketio(struct bb_session_request *);
