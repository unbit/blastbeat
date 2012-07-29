#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

/*

BlastBeat group management

Each virtualhost has its pool of groups.

Each group has a name in a hash table.

A group has a linked list of associated sessions
Each session has a linked list of all the subscribed groups

To join/create a group you send

SID, "join", "name"

if "name" already exists you will join the group, otherwise it will be created

To send a message to a group, you prefix it to the command:

SID, "mygroup:body", "<h1>Hello World</h1>"

this will send the body to all of the connected peers

When a session ends, it will be removed from all of the subscribed groups

*/

static uint32_t djb2_hash_group(char *key, size_t len, uint32_t mask) {

        uint32_t hash = 5381;
        size_t i;
	for(i=0;i<len;i++) {
        	hash = hash * 33 + key[i];
	}

        return (hash % mask);

}

static int bbg_compare(struct bb_group *bbg, char *name, size_t len) {
	if (bbg->len != len) return 0;
	return !memcmp(bbg->name, name, len);
}

// get a group by its name
static struct bb_group *ght_get(struct bb_virtualhost *vhost, char *name, size_t len) {

	uint32_t ght_pos = djb2_hash_group(name, len, vhost->ght_size);
        struct bb_group_entry *bbge = &vhost->ght[ght_pos];
        struct bb_group *bbg = bbge->head;
        while(bbg) {
                if (bbg_compare(bbg, name, len)) {
                        return bbg;
                }
                bbg = bbg->next;
        };
        return NULL;
}

// destroy a group
// BE SURE no sessions are mapped to them !!!

static void bb_group_destroy(struct bb_group *bbg) {
        // get the ht entry
        struct bb_group_entry *bbge = bbg->entry;
        // is it the first item ?
        if (bbg == bbge->head) {
                bbge->head = bbg->next;
        }
        // is it the last item ?
        if (bbg == bbge->tail) {
                bbge->tail = bbg->prev;
        }
        // prev entry ?
        if (bbg->prev) {
                bbg->prev->next = bbg->next;
        }
        //next entry ?
        if (bbg->next) {
                bbg->next->prev = bbg->prev;
        }

	free(bbg);
}


// leave a group

int bb_leave_group(struct bb_session *bbs, char *name, size_t len) {
	struct bb_group *bbg = ght_get(bbs->vhost, name, len);
	if (!bbg) return -1;

	return bb_session_leave_group(bbs, bbg);
}

int bb_session_leave_group(struct bb_session *bbs, struct bb_group *bbg) {

        struct bb_group_session *bbgs = NULL;

	// search for the group in the session
	struct bb_session_group *bbsg = bbs->groups;
	while(bbsg) {
		if (bbsg->group == bbg) {
			// remove the group from the session
			struct bb_session_group *prev = bbsg->prev;
			struct bb_session_group *next = bbsg->next;
			if (prev) {
				prev->next = next;
			}
			if (next) {
				next->prev = prev;
			}
			// fix bbs->groups (if required)
			if (bbsg == bbs->groups) {
				bbs->groups = next;
			}
			free(bbsg);
			goto found;
		}
		bbsg = bbsg->next;
	}
	return 0;
found:
	// remove the session from the group
	bbgs = bbg->sessions;
	while(bbgs) {
		if (bbgs->session == bbs) {
			struct bb_group_session *prev = bbgs->prev;
			struct bb_group_session *next = bbgs->next;
			if (prev) {
				prev->next = next;
			}
			if (next) {
				next->prev = prev;
			}
			if (bbgs == bbg->sessions) {
				bbg->sessions = next;
			}
			free(bbgs);
			break;
		}
		bbgs = bbgs->next;
	}

	// no more sessions in the group, remove it
	if (bbg->sessions == NULL) {
		bb_group_destroy(bbg);
	}



	return 0;
}

// add the group to the hash table

static struct bb_group *ght_add(struct bb_virtualhost *vhost, char *name, size_t len) {
        // get the hash
        uint32_t ht_pos = djb2_hash_group(name, len, vhost->ght_size);
        // get the ht entry
        struct bb_group_entry *bbge = &vhost->ght[ht_pos];

	struct bb_group *bbg = malloc(sizeof(struct bb_group));
	if (!bbg) {
		bb_error("malloc()");
		return NULL;
	}
	memcpy(bbg->name, name, len);
	bbg->len = len;
	bbg->vhost = vhost;
	bbg->sessions = NULL;
	
        // append session to entry
        if (!bbge->head) {
                bbg->prev = NULL;
                bbge->head = bbg;
        }
        else {
                bbg->prev = bbge->tail;
                bbge->tail->next = bbg;
        }
        bbg->entry = bbge;
        bbg->next = NULL;
        bbge->tail = bbg;

	return bbg;
}


/* join a group */

int bb_join_group(struct bb_session *bbs, char *name, size_t len) {
	// validate group name
	if (len > BLASTBEAT_MAX_GROUPNAME_LEN || len < 1) return -1;
	if (name[0] == '@') return -1;
	// get the groups mapped to the session
	struct bb_session_group *last_bbsg=NULL,*bbsg = NULL;

	// get the group from the vhost
	struct bb_group *bbg = ght_get(bbs->vhost, name, len);
	// create group if it does not exist
	if (!bbg) {
		bbg = ght_add(bbs->vhost, name, len);
	}
	if (!bbg) return -1;

	// get the list of already mapped sessions
	struct bb_group_session *last_bbgs = NULL,*bbgs = bbg->sessions;
	while(bbgs) {
		// this session is already mapped to that group
		if (bbgs->session == bbs) {
			goto found;
		}
		last_bbgs = bbgs;
		bbgs = bbgs->next;
	}

	// create a new session mapped in a group
	bbgs = malloc(sizeof(struct bb_group_session));
	if (!bbgs) {
		bb_error("malloc()");
		return -1;
	}
	bbgs->session = bbs;
	bbgs->next = NULL;

	if (last_bbgs) {
		last_bbgs->next = bbgs;
		bbgs->prev = last_bbgs;
	}
	else {
		bbg->sessions = bbgs;
		bbgs->prev = NULL;
	}

found:
	bbsg = bbs->groups;
	// now add the group to the session
	while(bbsg) {
		// the session is already joined
		if (bbsg->group == bbg) {
			return 0;
		}
		last_bbsg = bbsg;
		bbsg = bbsg->next;
	}

	// map the group into the session
	bbsg = malloc(sizeof(struct bb_session_group));
        if (!bbsg) {
                bb_error("malloc()");
                return -1;
        }
	bbsg->group = bbg;
	bbsg->next = NULL;

	if (last_bbsg) {
		last_bbsg->next = bbsg;
		bbsg->prev = last_bbsg;
	}
	else {
		bbs->groups = bbsg;
		bbsg->prev = NULL;
	}

	return 0;
}
