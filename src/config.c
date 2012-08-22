#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

/*
	ini parser taken from the uWSGI project
	ini file must be read ALL into memory.
	This memory must not be freed for all the server lifecycle
*/

#define is_opt(x) if (!strcmp(key, x))

static int count_chars(char *str, char what) {
	char *ptr = str;
	int count = 0;
	while(*ptr++) {
		if (*ptr == what)
			count++;
	}
	return count;
} 

static void bb_main_config_add(char *, char *);
static void bb_vhost_config_add(char *, char *, char *);

static uint32_t djb2_hash_hostname(char *key, size_t len) {

        uint32_t hash = 5381;
        size_t i;
        for(i=0;i<len;i++) {
                hash = hash * 33 + key[i];
        }

        return (hash % BLASTBEAT_HOSTNAME_HTSIZE);

}

static int bb_hostname_compare(struct bb_hostname *bbhn, char *name, size_t len) {
        if (bbhn->len != len) return 0;
        return !memcmp(bbhn->name, name, len);
}

// add the hostname to the hostnames hash
static int bb_hostname_add(char *name, size_t len, struct bb_virtualhost *vhost) {

	struct bb_virtualhost *already = bb_vhost_get(name, len, NULL);
	if (already) {
		fprintf(stderr,"!!! hostname \"%.*s\" is already configured for virtualhost \"%.*s\" !!!\n", (int) len, name, (int) already->len, already->name);
		return -1;
	}
        // get the hash
        uint32_t hnht_pos = djb2_hash_hostname(name, len);
        // get the first hostname
        struct bb_hostname *bbhn_last = NULL,*bbhn = blastbeat.hnht[hnht_pos];
	while(bbhn) {
		bbhn_last = bbhn;
		bbhn = bbhn->next;
	}
	
        bbhn = bb_alloc(sizeof(struct bb_hostname));
        if (!bbhn) {
                bb_error_exit("unable to allocate memory for hostname: malloc()");
        }
        bbhn->name = name;
        bbhn->len = len;
        bbhn->vhost = vhost;
        bbhn->next = NULL;

        if (bbhn_last) {
		bbhn_last->next = bbhn;
        }
        else {
		blastbeat.hnht[hnht_pos] = bbhn;
        }

	return 0;
}

// get a vhost by hostname
struct bb_virtualhost *bb_vhost_get(char *name, size_t len, struct bb_hostname **hostname) {

        uint32_t hnht_pos = djb2_hash_hostname(name, len);
        struct bb_hostname *bbhn = blastbeat.hnht[hnht_pos];
        while(bbhn) {
                if (bb_hostname_compare(bbhn, name, len)) {
			if (hostname) {
				*hostname = bbhn;
			}
                        return bbhn->vhost;
                }
                bbhn = bbhn->next;
        };
        return NULL;
}


static struct bb_acceptor *bb_get_acceptor(char *addr, int shared, void (*func)(struct bb_acceptor *)) {
	struct bb_acceptor *last_acceptor = NULL, *acceptor;
	union bb_addr bba;
	socklen_t addr_len;
	memset(&bba, 0, sizeof(bba));
 
	uint64_t priority = 1;
        char *space = strchr(addr, ' ');
        if (space) {
        	*space = 0;
                priority = strtoll(space+1, NULL, 10);
        }


	char *colon = strrchr(addr, ':');
        if (!colon) {
        	fprintf(stderr,"config error: invalid 'bind' syntax, must be addr:port\n");
                exit(1);
        }
        *colon = 0;
	if (count_chars(addr, ':') > 1) {
		char *percent = strchr(addr, '%');
		if (percent) {
			bba.in6.sin6_scope_id = if_nametoindex(percent+1);
			*percent = 0;
		}
		if (inet_pton(AF_INET6, addr, &bba.in6.sin6_addr) <= 0) {
			bb_error_exit("unable to parse IPv6 address: inet_pton()");
		}
		if (percent) {
			*percent = '%';
		}
		bba.in6.sin6_family = AF_INET6;
		bba.in6.sin6_port = htons(atoi(colon+1));
		addr_len = sizeof(struct sockaddr_in6);
		goto check;
	}
	if (inet_pton(AF_INET, addr, &bba.in4.sin_addr) <= 0) {
		bb_error_exit("unable to parse IPv4 address: inet_pton()");
	}
	bba.in4.sin_family = AF_INET;
	bba.in4.sin_port = htons(atoi(colon+1));
	addr_len = sizeof(struct sockaddr_in);

check:
	acceptor = blastbeat.acceptors;
	while(acceptor) {
		// acceptor already configured ?
		if (!memcmp(&acceptor->addr, &bba, sizeof(bba)))
			return acceptor;
		last_acceptor = acceptor;
		acceptor = acceptor->next;
	}

	acceptor = bb_alloc(sizeof(struct bb_acceptor));
	if (!acceptor) {
		bb_error_exit("unable to allocate memory for the new aceptor: malloc()");
	}	
	memset(acceptor, 0, sizeof(struct bb_acceptor));
	acceptor->shared = shared;
	acceptor->name = addr;
	acceptor->priority = priority;
	acceptor->port_str = colon;
	acceptor->read = bb_http_read;
	acceptor->write = bb_http_write;
	// fix address name
	*colon = ':';
	memcpy(&acceptor->addr, &bba, sizeof(bba));
	acceptor->addr_len = addr_len;

	if (!blastbeat.acceptors) {
		blastbeat.acceptors = acceptor;
	}
	else {
		last_acceptor->next = acceptor;
	}

	if (func) {
		func(acceptor);
	}

	return acceptor;
}

static struct bb_virtualhost *get_or_create_vhost(char *vhostname) {
	struct bb_virtualhost *last_vhost = NULL,*vhost = blastbeat.vhosts;
	// do not be afraid of using strcmp() as the config parser is the only one
	// allowed to create vhost
	while(vhost) {
		if (!strcmp(vhost->name, vhostname)) {
			return vhost;
		}
		last_vhost = vhost;
		vhost = vhost->next;
	}

	vhost = bb_alloc(sizeof(struct bb_virtualhost));
	if (!vhost) {
		bb_error_exit("malloc()");
	}
	memset(vhost, 0, sizeof(struct bb_virtualhost));
	vhost->name = vhostname;
	vhost->len = strlen(vhostname);

	// create the groups hashtable
	vhost->ght_size = 65536;
	vhost->ght = bb_alloc(sizeof(struct bb_group_entry) * vhost->ght_size);
	if (!vhost->ght) {
		bb_error_exit("malloc()");
	}

	if (last_vhost) {
		last_vhost->next = vhost;
	}
	else {
		blastbeat.vhosts = vhost;
	}

	if (bb_hostname_add(vhost->name, vhost->len, vhost)) {
		fprintf(stderr,"!!! the virtualhost \"%.*s\" will never be used !!!\n", (int) vhost->len, vhost->name);
	}
	return vhost;
}

static struct bb_dealer *get_or_create_dealer(char *node) {
	struct bb_dealer *last_bbd = NULL,*bbd = blastbeat.dealers;
        while(bbd) {
                if (!strcmp(bbd->identity, node)) {
                        return bbd;
                }
                last_bbd = bbd;
                bbd = bbd->next;
        }

	bbd = bb_alloc(sizeof(struct bb_dealer));
	if (!bbd) {
		bb_error_exit("malloc()");
	}
	memset(bbd, 0, sizeof(struct bb_dealer));
	bbd->identity = node;
	bbd->len = strlen(node);

	if (last_bbd) {
		last_bbd->next = bbd;
	}
	else {
		blastbeat.dealers = bbd;
	}	

	return bbd;
}

static struct bb_vhost_dealer *create_vhost_dealer(struct bb_virtualhost *vhost, char *node) {
	struct bb_dealer *bbd = get_or_create_dealer(node);
	struct bb_vhost_dealer *last_bbvhd = NULL,*bbvhd = vhost->dealers;
	while(bbvhd) {
		if (!strcmp(bbvhd->dealer->identity, node)) {
			return bbvhd;
		}
		last_bbvhd = bbvhd;
		bbvhd = bbvhd->next;
	}	

	bbvhd = bb_alloc(sizeof(struct bb_vhost_dealer));
	if (!bbvhd) {
		bb_error_exit("malloc()");
	}
	bbvhd->dealer = bbd;
	bbvhd->next = NULL;

	if (last_bbvhd) {
		last_bbvhd->next = bbvhd;
	}
	else {
		vhost->dealers = bbvhd;
	}

	return bbvhd;
}

static void ini_rstrip(char *line) {

	off_t i;

	for(i = strlen(line)-1;i>=0; i--) {
		if (line[i] == ' ' || line[i] == '\t' || line[i] == '\r') {
			line[i] = 0;
			continue;
		}
		break;
	}
}

static char *ini_lstrip(char *line) {

	off_t i;
	char *ptr = line;

	for(i=0;i< (int) strlen(line);i++) {
		if (line[i] == ' ' || line[i] == '\t' || line[i] == '\r') {
			ptr++;
			continue;
		}
		break;
	}

	return ptr;
}

static char *ini_get_key(char *key) {

	off_t i;
	char *ptr = key;

	for(i=0;i< (int) strlen(key);i++) {
		ptr++;
		if (key[i] == '=') {
			key[i] = 0;
			return ptr;
		}
	}

	return ptr;
}

static char *ini_get_line(char *ini, off_t size) {

	off_t i;
	char *ptr = ini;

	for(i=0;i<size;i++) {
		ptr++;
		if (ini[i] == '\n') {
			ini[i] = 0;
			return ptr;
		}
	}

	// check if it is a stupid file without \n at the end
	if (ptr > ini) {
		return ptr;
	}

	return NULL;

}

void bb_ini_config(char *file) {

	char *ini_line;

	char *section = "";
	char *key;
	char *val;

	int lines = 1;
	struct stat st;

	int fd = open(file, O_RDONLY);
	if (fd < 0) {
		bb_error_exit("error opening blastbeat config file: open()");
	}

	if (fstat(fd, &st)) {
		bb_error_exit("error reading blastbeat config file: stat()");
	}

	char *ini = bb_alloc(st.st_size + 1);
	if (!ini) {
		bb_error_exit("error reading blastbeat config file: malloc()");
	}

	ssize_t rlen = read(fd, ini, st.st_size);
	if (rlen != st.st_size) {
		bb_error_exit("error reading blastbeat config file: malloc()");
	}
	ini[st.st_size] = 0;	
	close(fd);

	size_t len = st.st_size;

	while(len) {
		ini_line = ini_get_line(ini, len);
		if (ini_line == NULL) {
			break;
		}
		lines++;

		// skip empty line
		key = ini_lstrip(ini);
		ini_rstrip(key);
		if (key[0] != 0) {
			if (key[0] == '[') {
				section = key+1;
				section[strlen(section)-1] = 0;
			}
			else if (key[0] == ';' || key[0] == '#') {
				// this is a comment
			}
			else {
				// val is always valid, but (obviously) can be ignored
				val = ini_get_key(key);
				ini_rstrip(key);
				val = ini_lstrip(val);
				ini_rstrip(val);

				if (!strcmp(section, "blastbeat")) {
					bb_main_config_add(key, val);
				}
				else if (!strncmp(section, "blastbeat:", 10)) {
					bb_vhost_config_add(section + 10, key, val);
				}
			}
		}


		len -= (ini_line - ini);
		ini += (ini_line - ini);
	}

}

void bb_vhost_push_acceptor(struct bb_virtualhost *vhost, struct bb_acceptor *acceptor) {
	
	struct bb_vhost_acceptor *last_bbva = NULL, *bbva = vhost->acceptors;
	while(bbva) {
		// acceptor already mapped
		if (bbva->acceptor == acceptor) {
			return;
		}
		last_bbva = bbva;
		bbva = bbva->next;
	}

	bbva = bb_alloc(sizeof(struct bb_vhost_acceptor));
	if (!bbva) {
		bb_error_exit("malloc()");
	}	
	bbva->acceptor = acceptor;
	bbva->next = NULL;

	if (last_bbva) {
		last_bbva->next = bbva;
	}
	else {
		vhost->acceptors = bbva;
	}
}

static void bb_add_router(char *name, struct bb_virtualhost *vhost) {
	struct bb_router *last_bbr = NULL, *bbr = blastbeat.routers;

	while(bbr) {
		last_bbr = bbr;
		bbr = bbr->next;
	}

	bbr = bb_alloc(sizeof(struct bb_router));
	memset(bbr, 0, sizeof(struct bb_router));

	bbr->zmq = name;
	bbr->vhost = vhost;

	if (last_bbr) {
		last_bbr->next = bbr;
	}
	else {
		blastbeat.routers = bbr;
	}
}

static void bb_main_config_add(char *key, char *value) {

        is_opt( "bind") {
                bb_get_acceptor(value, 1, NULL);
                return;
        }

        is_opt( "bind-ssl") {
                bb_get_acceptor(value, 1, bb_socket_ssl);
                return;
        }

        is_opt( "zmq") {
		bb_add_router(value, NULL);
                return;
        }

        is_opt("ping-freq") {
                blastbeat.ping_freq = atof(value);
                return;
        }

        is_opt("stats-freq") {
                blastbeat.stats_freq = atof(value);
                return;
        }

        is_opt("uid") {
                blastbeat.uid = value;
                return;
        }

        is_opt("gid") {
                blastbeat.gid = value;
                return;
        }

        is_opt("max-hops") {
                blastbeat.max_hops = atoi(value);
                return;
        }

        is_opt("sessions") {
                blastbeat.max_sessions = strtoll(value, NULL, 10);
                return;
        }

        is_opt( "timeout") {
		blastbeat.timeout = strtoll(value, NULL, 10);
                return;
        }

        is_opt( "writequeue-buffer") {
		blastbeat.writequeue_buffer = strtoll(value, NULL, 10);
                return;
        }

        is_opt( "memory") {
		blastbeat.max_memory = strtoll(value, NULL, 10);
                return;
        }

        is_opt( "max-headers") {
		blastbeat.max_headers = strtoll(value, NULL, 10);
                return;
        }

}

static void bb_vhost_config_add(char *vhostname, char *key, char *value) {
        struct bb_virtualhost *vhost = get_or_create_vhost(vhostname);

        is_opt( "bind") {
                struct bb_acceptor *acceptor = bb_get_acceptor(value, 0, NULL);
		bb_vhost_push_acceptor(vhost, acceptor);
                return;
        }

        is_opt( "bind-ssl") {
                struct bb_acceptor *acceptor = bb_get_acceptor(value, 0, bb_socket_ssl);
		bb_vhost_push_acceptor(vhost, acceptor);
                return;
        }

        is_opt( "certificate") {
		vhost->ssl_certificate = value;
                return;
        }

        is_opt( "key") {
		vhost->ssl_key = value;
                return;
        }

        is_opt( "sessions") {
		vhost->max_sessions = strtoll(value, NULL, 10);
                return;
        }

        is_opt( "node") {
                create_vhost_dealer(vhost, value);
                return;
        }

	is_opt( "cache") {
		vhost->cache_size = strtoll(value, NULL, 10)*(1024*1024);
		return;
	}

        is_opt( "alias") {
		bb_hostname_add(value, strlen(value), vhost);
                return;
        }

        is_opt( "timeout") {
		vhost->timeout = strtoll(value, NULL, 10);
                return;
        }

        is_opt( "zmq") {
		bb_add_router(value, vhost);
                return;
        }

        is_opt( "bandwidth") {
		// kbit/s
		vhost->bandwidth = strtoll(value, NULL, 10) * 1000;
		// translate it to bytes
		vhost->bandwidth = vhost->bandwidth/8;
                return;
        }

        return;
}

