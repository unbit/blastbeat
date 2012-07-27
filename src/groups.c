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

#define BLASTBEAT_MAX_GROUPNAME_LEN	64

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

static struct bb_group *ght_get(struct bb_virtualhost *vhost, char *name, size_t len) {

	uint32_t ght_pos = djb2_hash_group(name, len, vhost->ght_size);
        struct bb_group_entry *bbge = vhost->ght[ght_pos];
        struct bb_group *bbg = bbge->head;
        while(bbg) {
                if (bbg_compare(bbg, name, len)) {
                        return bbg;
                }
                bbg = bbg->next;
        };
        return NULL;
}

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

int bb_leave_group(struct bb_session *bbs, char *name, size_t len) {
	struct bb_group *bbg = ght_get(bbs->vhost, name, len);
	if (!bbg) return -1;

	// search for the group in the session
	struct bb_session_group *bbsg = bbs->groups;
	while(bbsg) {
		if (bbsg->group == bbg) {
			goto found;
		}
		bbsg = bbsg->next;
	}
	return 0;
found:
	// remove the group from the session
	...

	// remove the session from the group

        ...

	// no more sessions in the group, remove it
	if (bbg->sessions == NULL) {
		bb_group_destroy(bbg);
	}

	return 0;
}

int bb_join_group(struct bb_session *bbs, char *name, size_t len) {

	struct bb_group *bbg = ght_get(bbs->vhost, name, len);
	// create group if it does not exist
	if (!bbg) {
		bbg = ght_add(bbs->vhost, name, len);
	}
	if (!bbg) return -1;

	struct bb_group_session *last_bbgs = NULL,*bbgs = bbg->sessions;
	while(bbgs) {
		if (bbgs->session == bbs) {
			goto group;
		}
		last_bbgs = bbgs;
		bbgs = bbgs->next;
	}

	bbgs = malloc(sizeof(struct bb_group_session));
	if (!bbgs) {
		bb_error("malloc()");
		return -1;
	}
	bbgs->session = bbs;
	bbgs->next = NULL;

	if (last_bbgs) {
		last_bbgs->next = bbgs;
	}
	else {
		bbg->sessions = bbgs;
	}

group:
	// now add the group to the session
	struct bb_session_group *last_bbsg,*bbsg = bbs->groups;
	while(bbsg) {
		if (bbsg->group == bbg) {
			return 0;
		}
		last_bbsg = bbsg;
		bbsg = bbsg->next;
	}

	bbsg = malloc(sizeof(struct bb_session_group));
        if (!bbsg) {
                bb_error("malloc()");
                return -1;
        }
	bbsg->group = bbg;
	bbsg->next = NULL;

	if (last_bbsg) {
		last_bbsg->next = bbsg;
	}
	else {
		bbs->groups = bbsg;
	}

	return 0;
}
