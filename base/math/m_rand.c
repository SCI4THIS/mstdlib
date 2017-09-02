/* The MIT License (MIT)
 * 
 * Copyright (c) 2016 Main Street Softworks, Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

/* Random algorithm: xoroshiro128+ PRNG developed by David Blackman and Sebastiano Vigna.
 * Uses public domain implementation of the algorithm. */

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#include "m_config.h"

#include <mstdlib/mstdlib.h>

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

struct M_rand {
	M_uint64 s[2];
};

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

static const M_uint64 M_RAND_XOROSHIRO128P_JUMP[] = { 0xBEAC0467EBA5FACBULL, 0xD86B048B86AA9922ULL };

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

static __inline__ M_uint64 M_rand_rotate_left(M_uint64 v, int r)
{
	return (v << r) | (v >> (64 - r));
}

static M_uint64 M_rand_splitmix64(M_uint64 seed)
{
	seed += 0x9E3779B97F4A7C15ULL;
	seed = (seed ^ (seed >> 30)) * 0xBF58476D1CE4E5B9ULL;
	seed = (seed ^ (seed >> 27)) * 0x94D049BB133111EBULL;
	seed = seed ^ (seed >> 31);
	return seed;
}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

M_rand_t *M_rand_create(M_uint64 seed)
{
	M_rand_t    *state;
	M_timeval_t  tv;

	state = M_malloc_zero(sizeof(*state));
	/* Seed cannot be 0. */
	if (seed == 0) {
		/* Try to create a non-guessable seed. */
		M_time_gettimeofday(&tv);

		/* Seed with current time to the microsecond.
		 * tv_usec max size is 999999, so only represents about 20 bits, and
		 * tv_sec is only about 32bits right now (at least till 2038), so this
		 * should be combined into 1 64bit value */
		seed  = (M_uint64)tv.tv_sec << 20 | (M_uint64)tv.tv_usec;

		/* Seed with the addresses of both a stack variable address and a heap
		 * variable address.  This is even a bigger win for systems with ASLR.
		 * The actual address space on a 64bit system is typically only 48bits,
		 * so we might throw away some bits for high addresses, but we'd have
		 * a lot of guaranteed zeros in the high bounds without shifting one
		 * of the values to the upper 32bits */
		seed ^= ((M_uint64)&tv) << 32 | (M_uint64)state;
	}

	/* Recommended to seed splitmix64 and use it's output for
 	 * seeding xorshift */
	state->s[0] = M_rand_splitmix64(seed);
	state->s[1] = seed; /* splitmix64(seed ^ state->s[0]);
	                     *  -- randomness of "seed" should be pretty good,
	                     *     splitmix64 might throw too much entropy away if
	                     *     we use it for both halves. */

	M_rand_jump(state);
	return state;
}

void M_rand_destroy(M_rand_t *state)
{
	if (state == NULL)
		return;
	M_free(state);
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

M_uint64 M_rand(M_rand_t *state)
{
	M_uint64 s0;
	M_uint64 s1;
	M_bool   destroy_state = M_FALSE;
	M_uint64 ret;

	if (state == NULL) {
		state = M_rand_create(0);
		destroy_state = M_TRUE;
	}

	s0  = state->s[0];
	s1  = state->s[1];
	ret = s0 + s1;

	s1 ^= s0;
	state->s[0] = M_rand_rotate_left(s0, 55) ^ s1 ^ (s1 << 14);
	state->s[1] = M_rand_rotate_left(s1, 36);

	if (destroy_state)
		M_rand_destroy(state);
	return ret;
}

/* returns [min, max) */
M_uint64 M_rand_range(M_rand_t *state, M_uint64 min, M_uint64 max)
{
	M_uint64 r;
	M_uint64 range;
	M_uint64 ret;
	M_bool   destroy_state = M_FALSE;

	if (min >= max) {
		if (min == max) {
			return min;
		}
		return 0;
	}

	if (state == NULL) {
		state         = M_rand_create(0);
		destroy_state = M_TRUE;
	}

 	/* Divide M_RAND_MAX into groups based on the range between min and max.
 	 * We want to have an even count of adjacent number represent a reduced number. The
	 * idea being a random distribution will randomly have a number fall in the group.
	 *
 	 * If M_RAND_MAX can't be divided evenly we'll end up with a tail smaller than the
	 * other groups. If we fall within a group (not tail) then we return the group
	 * position as our reduced random number. If we fall in the tail we try again.
	 *
	 * What we'll end up with is something like this:
	 *
	 * M_RAND_MAX=100, min=5, max=32. Our range is 27. 100/27 is 3 groups of 3.
	 * [0..27..54..(81-100 is the tail)]
	 * [0,2]/3 = 0
	 * [3,5]/3 = 1
	 * ...
	 * [79,80]/3 = 26
	 * [81,100] = try again
	 */
	range = max - min;
	r     = M_rand(state);
	if (r >= M_RAND_MAX - (M_RAND_MAX % range)) {
		ret = M_rand_range(state, min, max);
	} else {
		ret = min + (r / (M_RAND_MAX / range));
	}

	if (destroy_state)
		M_rand_destroy(state);
	return ret;
}

/* returns [0, max) */
M_uint64 M_rand_max(M_rand_t *state, M_uint64 max)
{
	return M_rand_range(state, 0, max);
}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

M_rand_t *M_rand_duplicate(M_rand_t *state)
{
	M_rand_t *dstate;

	if (state == NULL)
		return M_rand_create(0);

	dstate       = M_malloc_zero(sizeof(*state));
	dstate->s[0] = state->s[0];
	dstate->s[1] = state->s[1];

	return dstate;
}

void M_rand_jump(M_rand_t *state)
{
	M_uint64 s0 = 0;
	M_uint64 s1 = 0;
	size_t   i;
	size_t   b;

	if (state == NULL)
		return;

	for(i=0; i<sizeof(M_RAND_XOROSHIRO128P_JUMP)/sizeof(*M_RAND_XOROSHIRO128P_JUMP); i++) {
		for(b=0; b<64; b++) {
			if (M_RAND_XOROSHIRO128P_JUMP[i] & 1ULL << b) {
				s0 ^= state->s[0];
				s1 ^= state->s[1];
			}
			M_rand(state);
		}
	}

	state->s[0] = s0;
	state->s[1] = s1;
}
