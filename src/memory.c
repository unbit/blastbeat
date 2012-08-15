/*

	BlastBeat memory allocator

	it is simply based on malloc/free but tracks
	every allocation to maintain memory limits

*/

#include "../blastbeat.h"

extern struct blastbeat_server blastbeat;

void *bb_alloc(size_t len) {
	if (blastbeat.allocated_memory+len > blastbeat.max_memory) {
		return NULL;
	}

	void *mem = malloc(len);
	if (!mem) {
		bb_error("malloc()");
		return NULL;
	}

	blastbeat.allocated_memory+=len;
	return mem;
}

void *bb_realloc(void *mem, size_t old_len, ssize_t len) {
	if (blastbeat.allocated_memory+len > blastbeat.max_memory) {
		return NULL;
	}

	void *new_mem = realloc(mem, old_len + len);
	if (!new_mem) {
		bb_error("realloc()");	
		return NULL;
	}

	blastbeat.allocated_memory+=len;
	return new_mem;
}

void bb_free(void *mem, size_t len) {
	if (len > blastbeat.allocated_memory-blastbeat.startup_memory) {
		fprintf(stderr, "BUG in memory accounting !!!\n");
	}
	else {
		blastbeat.allocated_memory-=len;
	}
	free(mem);
}
