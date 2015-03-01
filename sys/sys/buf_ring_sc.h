/*-
 * Copyright (c) 2007-2015 Kip Macy <kmacy@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 *
 */

#ifndef	_SYS_BUF_RING_SC_H_
#define	_SYS_BUF_RING_SC_H_

#include <machine/cpu.h>
struct buf_ring_sc;

struct buf_ring_sc_stats_v0 {
	uint64_t brs_enqueues;
	uint64_t brs_drops;
	uint64_t brs_abdications;
	uint64_t brs_stalls;
	uint64_t brs_starts;
	uint64_t brs_restarts;
};

#define ESTALLED        254      /* consumer is stalled */
#define EOWNED          255      /* consumer lock acquired */
typedef enum br_unlock_reason_ {
	BR_UNLOCK_IDLE = 1,
	BR_UNLOCK_ABDICATE,
	BR_UNLOCK_STALLED
} br_unlock_reason;

/* cache line align buf ring entries */
#define BR_FLAGS_ALIGNED 0x1

struct buf_ring_sc *buf_ring_sc_alloc(int count, struct malloc_type *type, int mflags, int brflags);
void buf_ring_sc_free(struct buf_ring_sc *br, struct malloc_type *type);
void buf_ring_sc_reset_stats(struct buf_ring_sc *br);
void buf_ring_sc_get_stats_v0(struct buf_ring_sc *br, struct buf_ring_sc_stats_v0 *brss);

/**
 * buf_ring_sc_enqueue - enqueue a buffer to the ring, possibly
 *  acquiring the consumer lock
 * @buf: buffer to enqueue
 *
 * return values:
 *  - 0        - success
 *  - ENOBUFS  - failure
 *  - ESTALLED - success, but the underlying driver is stalled
 *  - EOWNED   - success and caller is the new owner
 *
 */
int buf_ring_sc_enqueue(struct buf_ring_sc *br, void *buf);

/**
 * PROPOSED:
 * buf_ring_sc_enqueue_multi - batch enqueue buffers to the ring, 
 * possibly acquiring the consumer lock
 * @ents: array of buffers to enqueue
 * @ent_count: size of ents
 * @qcount: the number of buffers enqueued
 * return values:
 *  - 0        - success
 *  - ENOBUFS  - failure
 *  - ESTALLED - success, but the underlying driver is stalled
 *  - EOWNED   - success and caller is the new owner
 *
 */
int buf_ring_sc_enqueue_multi(struct buf_ring_sc *br, void *ents[], int ent_count, int *qcount);

/**
 * PROPOSED:
 * buf_ring_sc_enqueue_multi_atomic - batch enqueue buffers to the ring, 
 * possibly acquiring the consumer lock
 *
 * @ents: array of buffers to enqueue
 * @ent_count: size of ents
 * return values:
 *  - 0        - success
 *  - ENOBUFS  - failed to enqueue all buffers
 *  - ESTALLED - success, but the underlying driver is stalled
 *  - EOWNED   - success and caller is the new owner
 *
 */
int buf_ring_sc_enqueue_multi_atomic(struct buf_ring_sc *br, void *ents[], int ent_count);

/**
 * buf_ring_sc_peek - check ring for entries
 * @ents: array of returned values
 * @count: the size of ents
 *
 * returns: number of entries in ents
 *
 * populate ents with up to count entries from the ring
 * returns the number of entries in ents
 */
int buf_ring_sc_peek(struct buf_ring_sc *br, void *ents[], uint16_t count);

/**
 * buf_ring_sc_putback - return a buffer to the ring
 * @new: buffer to return
 * @idx: offset from consumer index to return it to
 *
 * Used to return a buffer (most likely already there)
 * to the top of the ring at offset idx from the current
 * consumer index. The caller should *not* have advanced 
 * the index.
 */
void buf_ring_sc_putback(struct buf_ring_sc *br, void *new, int idx);

/*
 * Advance the ring's consumer index by count
 */
void buf_ring_sc_advance(struct buf_ring_sc *br, int count);

/**
 * buf_ring_sc_abdicate - indicate unlock intent
 *
 * Mark the ring as transitioning to unowned.
 * Returns in a critical section. Caller is responsible
 * for calling buf_ring_sc_unlock subsequently with no
 * intervening blocking operations
 * This function is an *optional* optimization to give a
 * wider window for handoff to the next consumer. 
 */
void buf_ring_sc_abdicate(struct buf_ring_sc *br);

/**
 * buf_ring_sc_lock - acquire consumer lock
 *
 * Used to acquire the tx lock in a context without any additional
 * new packets
 */
void buf_ring_sc_lock(struct buf_ring_sc *br);

/**
 * buf_ring_sc_trylock - attempt to acquire consumer lock
 *
 * Used to acquire the tx lock in a context without any additional
 * new packets
 */
int buf_ring_sc_trylock(struct buf_ring_sc *br);

/**
 * buf_ring_sc_unlock - release the consumer lock 
 * @reason: the reason why the lock is being dropped:
 *   - BR_UNLOCK_IDLE: there are no more packets
 *   - BR_UNLOCK_ABDICATE: there are more packets but we've
 *     used up our budget
 *   - BR_UNLOCK_STALLED: Unable to consume more packets from
 *     the ring due to some other resource limitation
 *
 * returns true if there is a pending owner - meaning that the
 * caller does not have to enqueue a task if there are still buffers
 * in the ring and we're abdicating
 */
int buf_ring_sc_unlock(struct buf_ring_sc *br, br_unlock_reason reason);
int buf_ring_sc_count(struct buf_ring_sc *br);
int buf_ring_sc_empty(struct buf_ring_sc *br);
int buf_ring_sc_full(struct buf_ring_sc *br);
#endif /* BUF_RING_SC_H_ */
