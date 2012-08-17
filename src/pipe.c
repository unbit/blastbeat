/*

	BlastBeat pipe system

	In high performance scenario (like video chat) you could need
	to fast-forward big messages to specific peers without passing to the dealer
        (your app).

	Take a websocket videochat as example: you want to forward frames generated
	by a producer to all of the consumer without processing it.

	The idea is in BlastBeat recognizing such messages, and forwarding them to specific
	sessions or groups without passing the messages to the dealers.

	The syntax is:

		zmq_send([sid, 'pipe', 'group:message_types'])
		zmq_send([sid, 'pipe', '@sid:message_types'])

		message_types is a list (comma separated) of the message types
		that must be piped (read: will not be passed to the dealer)

		In the webchat example, supposing a room where all the sessions
		are subscribed to the 'webcam' group:

		zmq_send([sid, 'pipe', 'webcam:websocket'])

		from now on all of the websocket messages will be parsed/check by blastbeat
		and directly forwarded to the piped peers.

*/

#include "../blastbeat.h"

// forward to peers (destination is checked on add)
// TODO is copy required for all peers ?
static void bb_pipe_websocket_to(struct bb_pipe *bbp, char *buf, size_t len) {
	// forward to a sid;
	if (bbp->dest[0] == '@') {
		struct bb_session *bbs = bb_sht_get(bbp->dest+1);
		if (!bbs) return;
		(void) bb_websocket_reply(bbs, buf, len);
		return;
	}

	struct bb_group *bbg = bb_ght_get(bbp->session->vhost, bbp->dest, bbp->dest_len);
	if (!bbg) return;
	struct bb_group_session *bbgs = bbg->sessions;
        while(bbgs) {
		if (bbgs->session == bbp->session && bbp->session->noecho) goto next;
		(void) bb_websocket_reply(bbgs->session, buf, len);
next:
        	bbgs = bbgs->next;
	}
}

static void bb_pipe_body_to(struct bb_pipe *bbp, char *buf, size_t len) {
        // forward to a sid;
        if (bbp->dest[0] == '@') {
                struct bb_session *bbs = bb_sht_get(bbp->dest+1);
                if (!bbs) return;
                (void) bbs->send_body(bbs, buf, len);
                return;
        }

        struct bb_group *bbg = bb_ght_get(bbp->session->vhost, bbp->dest, bbp->dest_len);
        if (!bbg) return;
        struct bb_group_session *bbgs = bbg->sessions;
        while(bbgs) {
		if (bbgs->session == bbp->session && bbp->session->noecho) goto next;
                (void) bbgs->session->send_body(bbgs->session, buf, len);
next:
                bbgs = bbgs->next;
        }
}


// scan the list of bb_pipe structures and forward them if matches
int bb_check_for_pipe(struct bb_session *bbs, char *msg_type, size_t msg_type_len, char *buf, size_t len) {
	int ret = 0;
	struct bb_pipe *bbp = bbs->pipes_head;
	while(bbp) {
		if (!bb_strcmp(msg_type, msg_type_len, "websocket", 9) && bbp->on_websocket) {
			ret = 1;
			bb_pipe_websocket_to(bbp, buf, len);			
			goto next;
		}
		if (!bb_strcmp(msg_type, msg_type_len, "body", 4) && bbp->on_body) {
                        ret = 1;
                        bb_pipe_body_to(bbp, buf, len);
                        goto next;
                }
next:
		bbp = bbp->next;
	}
	
	return ret;
}

static void bb_parse_pipe(struct bb_pipe *bbp, char *mt, size_t mt_len) {
	if (!bb_strcmp(mt, mt_len, "websocket", 9)) {
		bbp->on_websocket = 1;
	}
	else if (!bb_strcmp(mt, mt_len, "body", 4)) {
		bbp->on_body = 1;
	}
}

int bb_pipe_add(struct bb_session *bbs, char *args, size_t args_len) {
	off_t i;
	char *colon = memchr(args, ':', args_len);
	if (!colon) return -1;

	size_t dest_len = colon-args;
	if (dest_len > BLASTBEAT_MAX_GROUPNAME_LEN) return -1;
	if (dest_len == args_len) return -1;

	struct bb_pipe *bbp = bb_alloc(sizeof(struct bb_pipe));
	if (!bbp) {
		return -1;
	}
	memset(bbp, 0, sizeof(struct bb_pipe));

	bbp->session = bbs;
	memcpy(bbp->dest, args, dest_len);
	bbp->dest_len = dest_len;

	char *mt = colon+1;
	size_t mt_len = 0;
	for(i=dest_len;i<args_len;i++) {
		if (mt == NULL) mt = args+i;
		if (args[i] == ',') {
			bb_parse_pipe(bbp, mt, mt_len);
			mt = NULL;
			mt_len = 0;
			continue;
		}
		mt_len++;
	}

	if (mt_len > 0) {
		bb_parse_pipe(bbp, mt, mt_len-1);
	}

	// ok, now append the pipe, you can create multiple pipe of the same type
	// to duplicate messages, still need to find a usage for that :)

	// is it the first one ?
	if (!bbs->pipes_head) {
		bbs->pipes_head = bbp;
		bbp->prev = NULL;
	}
	else {
		bbs->pipes_tail->next = bbp;
		bbp->prev = bbs->pipes_tail;
	}
	bbs->pipes_tail = bbp;

	return 0;
}
