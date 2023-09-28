#include "common.h"

// Avoid pulling in any other headers.
typedef unsigned int uint32_t;

// murmurhash2 from
// https://github.com/aappleby/smhasher/blob/92cf3702fcfaadc84eb7bef59825a23e0cd84f56/src/MurmurHash2.cpp/*  */

unsigned long long hash_stack(stack_trace_t *stack, int seed) {
  const unsigned long long m = 0xc6a4a7935bd1e995LLU;
  const int r = 47;
  unsigned long long hash = seed ^ (stack->len * m);

  for(int i=0; i<MAX_STACK_DEPTH; i++){
    unsigned long long k = stack->addresses[i];

    k *= m;
    k ^= k >> r;
    k *= m;

    hash ^= k;
    hash *= m;
  }

  return hash;
}