#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

/*
	ini parser taken from the uWSGI project
	ini file must be read ALL into memory.
	This memory must not be freed for all the server lifecycle
*/

void bb_main_config_add(char *key, char *value) {

	if (!strcmp(key, "bind")) {
		char *colon = strchr(value, ':');
		if (!colon) {
			fprintf(stderr,"config error: invalid 'bind' syntax, must be addr:port\n");
		}
		*colon = 0;
		blastbeat.addr = value;
		blastbeat.port = atoi(colon+1);
		return;
	}

	if (!strcmp(key, "zmq")) {
		blastbeat.zmq = value;
		return;
	}

	if (!strcmp(key, "ping-freq")) {
		blastbeat.ping_freq = atof(value);
		return;
	}

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
		blastbeat.vhosts = vhost;
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

void bb_vhost_config_add(char *vhostname, char *key, char *value) {
	struct bb_virtualhost *vhost = get_or_create_vhost(vhostname);

	if (!strcmp(key, "node")) {
		create_dealer(vhost, value);
		return;
	}

	return;
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
