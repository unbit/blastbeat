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
void bb_pipe_to(struct bb_pipe *bbp, char *buf, size_t len) {
	// forward to a sid;
	if (bbp->dest[0] == '@') {
		struct bb_session *bbs = bb_sht_get(bbp->dest+1);
		if (!bbs) return;
		bb_wq_push_copy(bbs, buf, len, BB_WQ_FREE);
		return;
	}

	struct bb_group *bbg = bb_ght_get(bbp->session->vhost, bbp->dest, bbp->dest_len);
	struct bb_group_session *bbgs = bbg->sessions;
        while(bbgs) {
		bb_wq_push_copy(bbgs->session, buf, len, BB_WQ_FREE);
        	bbgs = bbgs->next;
	}
}

// scan the list of bb_pipe structures and forward them if matches
int bb_check_for_pipe(struct bb_session *bbs, char *msg_type, size_t msg_type_len, char *buf, size_t len) {
	int ret = 0;
	struct bb_pipe *bbp = bbs->pipes_head;
	while(bbp) {
		if (!bb_stricmp(msg_type, msg_type_len, "websocket", 9) && bbp->on_websocket) {
			ret = 1;
			bb_pipe_to(bbp, buf, len);			
			goto next;
		}
next:
		bbp = bbp->next;
	}
	
	return ret;
}
