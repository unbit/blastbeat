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

static struct bb_acceptor *bb_get_acceptor(char *addr, int shared) {
	struct bb_acceptor *last_acceptor, *acceptor;
	union bb_addr bba;
	memset(&bba, 0, sizeof(bba));

	char *colon = strrchr(addr, ':');
        if (!colon) {
        	fprintf(stderr,"config error: invalid 'bind' syntax, must be addr:port\n");
                exit(1);
        }
        *colon = 0;
#ifdef AF_INET6
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
		goto check;
	}
#endif
	if (inet_pton(AF_INET, addr, &bba.in4.sin_addr) <= 0) {
		bb_error_exit("unable to parse IPv4 address: inet_pton()");
	}
	bba.in4.sin_family = AF_INET;
	bba.in4.sin_port = htons(atoi(colon+1));

check:
	acceptor = blastbeat.acceptors;
	while(acceptor) {
		// acceptor already configured ?
		if (!memcmp(&acceptor->addr, &bba, sizeof(bba)))
			return acceptor;
		last_acceptor = acceptor;
		acceptor = acceptor->next;
	}

	acceptor = malloc(sizeof(struct bb_acceptor));
	if (!acceptor) {
		bb_error_exit("unable to allocate memory for the new aceptor: malloc()");
	}	
	memset(acceptor, 0, sizeof(struct bb_acceptor));
	acceptor->shared = shared;
	acceptor->name = addr;
	// fix address name
	*colon = ':';
	memcpy(&acceptor->addr, &bba, sizeof(bba));

	if (!blastbeat.acceptors) {
		blastbeat.acceptors = acceptor;
	}
	else {
		last_acceptor->next = acceptor;
	}

	return acceptor;
}

static struct bb_virtualhost *get_or_create_vhost(char *vhostname) {
	if (!blastbeat.acceptors) {
		fprintf(stderr, "you need to configure at leats one bind directive\n");
		exit(1);
	}
	struct bb_virtualhost *last_vhost = NULL,*vhost = blastbeat.acceptors->vhosts;
	// do not be afraid of using strcmp() as the config parser is the only one
	// allowed to create vhost
	while(vhost) {
		if (!strcmp(vhost->name, vhostname)) {
			return vhost;
		}
		last_vhost = vhost;
		vhost = vhost->next;
	}

	vhost = malloc(sizeof(struct bb_virtualhost));
	if (!vhost) {
		bb_error_exit("malloc()");
	}
	memset(vhost, 0, sizeof(struct bb_virtualhost));
	vhost->name = vhostname;
	vhost->len = strlen(vhostname);

	if (last_vhost) {
		last_vhost->next = vhost;
	}
	else {
		blastbeat.acceptors->vhosts = vhost;
	}
	return vhost;
}

static struct bb_dealer *create_dealer(struct bb_virtualhost *vhost, char *node) {
	struct bb_dealer *last_bbd = NULL,*bbd = vhost->dealers;
	while(bbd) {
		if (!strcmp(bbd->identity, node)) {
			return bbd;
		}
		last_bbd = bbd;
		bbd = bbd->next;	
	}
	
	bbd = malloc(sizeof(struct bb_dealer));
	if (!bbd) {
		bb_error_exit("malloc()");
	}
	memset(bbd, 0, sizeof(struct bb_dealer));
	bbd->identity = node;
	bbd->len = strlen(node);
	bbd->vhost = vhost;
	if (last_bbd) {
		last_bbd->next = bbd;
	}
	else {
		vhost->dealers = bbd;
	}
	return bbd;
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

	char *ini = malloc(st.st_size + 1);
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

static void bb_push_to_acceptor(struct bb_acceptor *acceptor, struct bb_virtualhost *vhost) {
	struct bb_virtualhost *vhosts = acceptor->vhosts;
	if (!vhosts) {
		struct bb_virtualhost *vcopy = malloc(sizeof(struct bb_virtualhost));
		if (!vcopy) {
			bb_error_exit("unable to allocate memory for virtualhost: malloc()");
		}
		memcpy(vcopy, vhost, sizeof(struct bb_virtualhost));
		vcopy->next = NULL;
		acceptor->vhosts = vcopy;
		return ;
	}
	
	while(vhosts) {
		if (!strcmp(vhost->name, vhosts->name)) return;
		if (!vhosts->next) {
			vhosts->next = malloc(sizeof(struct bb_virtualhost));
			if (!vhosts->next) {
                        	bb_error_exit("unable to allocate memory for virtualhost: malloc()");
                	}
			memcpy(vhosts->next, vhost, sizeof(struct bb_virtualhost));
			vhosts->next->next = NULL;
			return;
		}
next:
		vhosts = vhosts->next;
	}
}

static void bb_main_config_add(char *key, char *value) {

        is_opt( "bind") {
                bb_get_acceptor(value, 1);
                return;
        }

        is_opt( "zmq") {
                blastbeat.zmq = value;
                return;
        }

        is_opt("ping-freq") {
                blastbeat.ping_freq = atof(value);
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

}

static void bb_vhost_config_add(char *vhostname, char *key, char *value) {
        struct bb_virtualhost *vhost = get_or_create_vhost(vhostname);

        is_opt( "bind") {
                struct bb_acceptor *acceptor = bb_get_acceptor(value, 0);
		bb_push_to_acceptor(acceptor, vhost);
                return;
        }

        is_opt( "node") {
                create_dealer(vhost, value);
                return;
        }

        return;
}

