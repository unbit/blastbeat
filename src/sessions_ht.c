#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

/*

sessions hash table

each session is represented by a UUID value (128 bit)

This is the binary form of UUID, so if you want to print it to the 32bytes variant,
just do it in your client. Messages will always use the 16bytes raw representation.

The hast table has a fixed number of entries (by default 65536 (64k)). This is a good compromise, but in the future
i would like to allow the admin to tune it.

Each UUID is hashed with djb2 function, and masked with the maximum number of items.

Each entry is a linked list of bb_session structures.

*/

static uint32_t djb2_hash_uuid(char *key, uint32_t mask) {

	uint32_t hash = 5381;
	// yes i prefer to avoid the cycle here... (manual optimization :P)
	hash = hash * 33 + key[0];
	hash = hash * 33 + key[1];
	hash = hash * 33 + key[2];
	hash = hash * 33 + key[3];
	hash = hash * 33 + key[4];
	hash = hash * 33 + key[5];
	hash = hash * 33 + key[6];
	hash = hash * 33 + key[7];
	hash = hash * 33 + key[8];
	hash = hash * 33 + key[9];
	hash = hash * 33 + key[10];
	hash = hash * 33 + key[11];
	hash = hash * 33 + key[12];
	hash = hash * 33 + key[13];
	hash = hash * 33 + key[14];
	hash = hash * 33 + key[15];

	return (hash % mask);
	
}

static int bbs_compare(struct bb_session *bbs, char *uuid) {
	// a funny optimization, we split the uuid in 2 64bit numbers
	// and we compare them
	uint64_t *part1 = (uint64_t *) uuid;
	uint64_t *part2 = (uint64_t *) (uuid + 8);
	if (bbs->uuid_part1 != *part1) return 0;
	if (bbs->uuid_part2 != *part2) return 0;
	return 1;
}

struct bb_session *bb_sht_get(char *uuid) {
	uint32_t ht_pos = djb2_hash_uuid(uuid, blastbeat.sht_size);
	struct bb_session_entry *bbse = &blastbeat.sht[ht_pos];
	struct bb_session *bbs = bbse->head;
	while(bbs) {
		if (bbs_compare(bbs, uuid)) {
			return bbs;
		}
		bbs = bbs->next;
	};
	return NULL;
}

void bb_sht_add(struct bb_session *bbs) {
	// generate the uuid for the request
	uuid_generate((unsigned char *)&bbs->uuid_part1);
	// get the hash
	uint32_t ht_pos = djb2_hash_uuid((char *) &bbs->uuid_part1, blastbeat.sht_size);	
	// get the ht entry
	struct bb_session_entry *bbse = &blastbeat.sht[ht_pos];
	// append session to entry
	if (!bbse->head) {
		bbs->prev = NULL;
		bbse->head = bbs;
	}
	else {
		bbs->prev = bbse->tail;
		bbse->tail->next = bbs;
	}
	bbs->entry = bbse;
	bbs->next = NULL;
	bbse->tail = bbs;
}

void bb_sht_remove(struct bb_session *bbs) {
	// get the ht entry
        struct bb_session_entry *bbse = bbs->entry;
	// is it the first item ?
	if (bbs == bbse->head) {
		bbse->head = bbs->next;
	}
	// is it the last item ?
	if (bbs == bbse->tail) {
		bbse->tail = bbs->prev;
	}
	// prev entry ?
	if (bbs->prev) {
		bbs->prev->next = bbs->next;
	}
	//next entry ?
	if (bbs->next) {
		bbs->next->prev = bbs->prev;
	}

	if (bbs->vhost) {
		bbs->vhost->active_sessions--;
	}

	if (bbs->dealer) {
		bbs->dealer->load--;
	}
	blastbeat.active_sessions--;
}
