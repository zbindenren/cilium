/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016-2020 Authors of Cilium */

#ifndef __BPF_BUILTINS__
#define __BPF_BUILTINS__

#include "compiler.h"

#ifndef lock_xadd
# define lock_xadd(P, V)	((void) __sync_fetch_and_add((P), (V)))
#endif

#define __it(x, op) (x -= sizeof(__u##op))

static __always_inline void __bpf_unaligned_memset(void *d, const __u8 c,
						   __u64 len)
{
	if (!__builtin_constant_p(len))
		__throw_build_bug();

	switch (len) {
#define __it_set(a, b, op) (*(__u##op *)__it(a, op)) = b
	case 96: __it_set(d, c, 64);
	case 88: __it_set(d, c, 64);
	case 80: __it_set(d, c, 64);
	case 72: __it_set(d, c, 64);
	case 64: __it_set(d, c, 64);
	case 56: __it_set(d, c, 64);
	case 48: __it_set(d, c, 64);
	case 40: __it_set(d, c, 64);
	case 32: __it_set(d, c, 64);
	case 24: __it_set(d, c, 64);
	case 16: __it_set(d, c, 64);
	case  8: __it_set(d, c, 64);
		break;
	case 94: __it_set(d, c, 64);
	case 86: __it_set(d, c, 64);
	case 78: __it_set(d, c, 64);
	case 70: __it_set(d, c, 64);
	case 62: __it_set(d, c, 64);
	case 54: __it_set(d, c, 64);
	case 46: __it_set(d, c, 64);
	case 38: __it_set(d, c, 64);
	case 30: __it_set(d, c, 64);
	case 22: __it_set(d, c, 64);
	case 14: __it_set(d, c, 64);
	case  6: __it_set(d, c, 32);
		 __it_set(d, c, 16);
		break;
	case 92: __it_set(d, c, 64);
	case 84: __it_set(d, c, 64);
	case 76: __it_set(d, c, 64);
	case 68: __it_set(d, c, 64);
	case 60: __it_set(d, c, 64);
	case 52: __it_set(d, c, 64);
	case 44: __it_set(d, c, 64);
	case 36: __it_set(d, c, 64);
	case 28: __it_set(d, c, 64);
	case 20: __it_set(d, c, 64);
	case 12: __it_set(d, c, 64);
	case  4: __it_set(d, c, 32);
		break;
	case 90: __it_set(d, c, 64);
	case 82: __it_set(d, c, 64);
	case 74: __it_set(d, c, 64);
	case 66: __it_set(d, c, 64);
	case 58: __it_set(d, c, 64);
	case 50: __it_set(d, c, 64);
	case 42: __it_set(d, c, 64);
	case 34: __it_set(d, c, 64);
	case 26: __it_set(d, c, 64);
	case 18: __it_set(d, c, 64);
	case 10: __it_set(d, c, 64);
	case  2: __it_set(d, c, 16);
		break;
	case  1: __it_set(d, c, 8);
		break;
	default:
		/* __builtin_memset() is crappy slow since it cannot
		 * make any assumptions about alignment & underlying
		 * efficient unaligned access on the target we're
		 * running.
		 */
		__throw_build_bug();
	}
}

static __always_inline __maybe_unused void
__bpf_no_builtin_memset(void *d __maybe_unused, int c __maybe_unused,
			__u64 len __maybe_unused)
{
	__throw_build_bug();
}

/* Redirect any direct use in our code to throw an error. */
#define __builtin_memset	__bpf_no_builtin_memset

static __always_inline __nobuiltin("memset") void memset(void *d, int c, __u64 len)
{
	return __bpf_unaligned_memset(d, c, len);
}

static __always_inline void __bpf_unaligned_memcpy(void *d, const void *s,
						   __u64 len)
{
	if (!__builtin_constant_p(len))
		__throw_build_bug();

	switch (len) {
#define __it_mov(a, b, op) (*(__u##op *)__it(a, op)) = (*(__u##op *)__it(b, op))
	case 96: __it_mov(d, s, 64);
	case 88: __it_mov(d, s, 64);
	case 80: __it_mov(d, s, 64);
	case 72: __it_mov(d, s, 64);
	case 64: __it_mov(d, s, 64);
	case 56: __it_mov(d, s, 64);
	case 48: __it_mov(d, s, 64);
	case 40: __it_mov(d, s, 64);
	case 32: __it_mov(d, s, 64);
	case 24: __it_mov(d, s, 64);
	case 16: __it_mov(d, s, 64);
	case  8: __it_mov(d, s, 64);
		break;
	case 94: __it_mov(d, s, 64);
	case 86: __it_mov(d, s, 64);
	case 78: __it_mov(d, s, 64);
	case 70: __it_mov(d, s, 64);
	case 62: __it_mov(d, s, 64);
	case 54: __it_mov(d, s, 64);
	case 46: __it_mov(d, s, 64);
	case 38: __it_mov(d, s, 64);
	case 30: __it_mov(d, s, 64);
	case 22: __it_mov(d, s, 64);
	case 14: __it_mov(d, s, 64);
	case  6: __it_mov(d, s, 32);
		 __it_mov(d, s, 16);
		break;
	case 92: __it_mov(d, s, 64);
	case 84: __it_mov(d, s, 64);
	case 76: __it_mov(d, s, 64);
	case 68: __it_mov(d, s, 64);
	case 60: __it_mov(d, s, 64);
	case 52: __it_mov(d, s, 64);
	case 44: __it_mov(d, s, 64);
	case 36: __it_mov(d, s, 64);
	case 28: __it_mov(d, s, 64);
	case 20: __it_mov(d, s, 64);
	case 12: __it_mov(d, s, 64);
	case  4: __it_mov(d, s, 32);
		break;
	case 90: __it_mov(d, s, 64);
	case 82: __it_mov(d, s, 64);
	case 74: __it_mov(d, s, 64);
	case 66: __it_mov(d, s, 64);
	case 58: __it_mov(d, s, 64);
	case 50: __it_mov(d, s, 64);
	case 42: __it_mov(d, s, 64);
	case 34: __it_mov(d, s, 64);
	case 26: __it_mov(d, s, 64);
	case 18: __it_mov(d, s, 64);
	case 10: __it_mov(d, s, 64);
	case  2: __it_mov(d, s, 16);
		break;
	case  1: __it_mov(d, s, 8);
		break;
	default:
		/* __builtin_memcpy() is crappy slow since it cannot
		 * make any assumptions about alignment & underlying
		 * efficient unaligned access on the target we're
		 * running.
		 */
		__throw_build_bug();
	}
}

static __always_inline __maybe_unused void
__bpf_no_builtin_memcpy(void *d __maybe_unused, const void *s __maybe_unused,
			__u64 len __maybe_unused)
{
	__throw_build_bug();
}

/* Redirect any direct use in our code to throw an error. */
#define __builtin_memcpy	__bpf_no_builtin_memcpy

static __always_inline __nobuiltin("memcpy") void memcpy(void *d, const void *s,
							 __u64 len)
{
	return __bpf_unaligned_memcpy(d, s, len);
}

#ifndef memmove
# define memmove(D, S, N)	__builtin_memmove((D), (S), (N))
#endif

/* NOTE: https://llvm.org/bugs/show_bug.cgi?id=26218 */
#ifndef memcmp
# define memcmp(A, B, N)	__builtin_memcmp((A), (B), (N))
#endif

#endif /* __BPF_BUILTINS__ */
