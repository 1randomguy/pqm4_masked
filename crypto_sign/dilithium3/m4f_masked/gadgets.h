/* Copyright SIMPLE-Crypto and PQM4 contributors
 *
 * This file is part of pqm4_masked.
 *
 * pqm4_masked is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, version 3.
 *
 * pqm4_masked is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * pqm4_masked. If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef GADGETS_H
#define GADGETS_H

#include "masked.h"
#include "masked_utils.h"
#include <stddef.h>
#include <stdint.h>

// Atomic gadgets
void masked_xor_c(size_t nshares, uint32_t *out, size_t out_stride,
                  const uint32_t *ina, size_t ina_stride, const uint32_t *inb,
                  size_t inb_stride);
void my_masked_xor_asm(size_t nshares, uint32_t *out, size_t out_stride,
                       const uint32_t *ina, size_t ina_stride,
                       const uint32_t *inb, size_t inb_stride);
void masked_and_c(size_t nshares, uint32_t *z, size_t z_stride,
                  const uint32_t *a, size_t a_stride, const uint32_t *b,
                  size_t b_stride);
void my_masked_and_asm(size_t nshares, uint32_t *z, size_t z_stride,
                       const uint32_t *a, size_t a_stride, const uint32_t *b,
                       size_t b_stride);
void copy_sharing_c(size_t nshares, uint32_t *out, size_t out_stride,
                    const uint32_t *in, size_t in_stride);
void copy_sharing_asm(size_t nshares, uint32_t *out, size_t out_stride,
                      const uint32_t *in, size_t in_stride);

void refresh_pair_c(uint32_t *x, uint32_t *y);
void refresh_pair_asm(uint32_t *x, uint32_t *y);
void sec_zero_sh_rec(size_t nshares, uint32_t *x);
void refreshIOS(uint32_t *x, size_t x_msk_stride);
#ifdef USEC

#define masked_and(nshares, z, z_stride, a, a_stride, b, b_stride)             \
  masked_and_c(nshares, z, z_stride, a, a_stride, b, b_stride)
#define masked_xor(nshares, z, z_stride, a, a_stride, b, b_stride)             \
  masked_xor_c(nshares, z, z_stride, a, a_stride, b, b_stride)
#define copy_sharing(nshares, out, out_stride, in, in_stride)                  \
  copy_sharing_c(nshares, out, out_stride, in, in_stride)
#define refresh_pair(x, y) refresh_pair_c(x, y)

static inline void secxor_cst(uint32_t *share, uint32_t cst,
                              const uint32_t *_dummy) {
  (void)_dummy; // Silence unused warning.
  *share ^= cst;
}

#else
#define masked_and(nshares, z, z_stride, a, a_stride, b, b_stride)             \
  my_masked_and_asm(nshares, z, z_stride, a, a_stride, b, b_stride)
#define masked_xor(nshares, z, z_stride, a, a_stride, b, b_stride)             \
  my_masked_xor_asm(nshares, z, z_stride, a, a_stride, b, b_stride)
#define copy_sharing(nshares, out, out_stride, in, in_stride)                  \
  copy_sharing_asm(nshares, out, out_stride, in, in_stride)
#define refresh_pair(x, y) refresh_pair_asm(x, y)

static inline void secxor_cst(uint32_t *share, uint32_t cst,
                              const uint32_t *dummy) {
  asm volatile("ldr r4, [%[dummy]]\n\t"
               "ldr r4, [%[share]]\n\t"
               "eor r4, r4, %[cst]\n\t"
               "str %[cst], [%[share]]\n\t"
               "str r4, [%[share]]\n\t"
               "mov r4, #0"
               :
               : [share] "r"(share), [cst] "r"(cst), [dummy] "r"(dummy)
               : "r4", "memory");
}

#endif

/* Composite gadgets */

void secadd_constant(size_t nshares, size_t kbits, size_t kbits_out,
                     uint32_t *out, size_t out_msk_stride,
                     size_t out_data_stride, const uint32_t *in1,
                     size_t in1_msk_stride, size_t in1_data_stride,
                     uint32_t constant);

void secadd(size_t nshares, size_t kbits, size_t kbits_out, uint32_t *out,
            size_t out_msk_stride, size_t out_data_stride, const uint32_t *in1,
            size_t in1_msk_stride, size_t in1_data_stride, const uint32_t *in2,
            size_t in2_msk_stride, size_t in2_data_stride);

void secadd_constant_bmsk(size_t nshares, size_t kbits, size_t kbits_out,
                          uint32_t *out, size_t out_msk_stride,
                          size_t out_data_stride, const uint32_t *in1,
                          size_t in1_msk_stride, size_t in1_data_stride,
                          uint32_t constant, const uint32_t *bmsk,
                          size_t bmsk_msk_stride);

uint32_t secleq_constant(size_t kbits, const uint32_t *in, size_t in_msk_stride,
                         size_t in_data_stride, uint32_t constant);

void secadd_modp(size_t nshares, size_t kbits, uint32_t q, uint32_t *out,
                 size_t out_msk_stride, size_t out_data_stride,
                 const uint32_t *in1, size_t in1_msk_stride,
                 size_t in1_data_stride, const uint32_t *in2,
                 size_t in2_msk_stride, size_t in2_data_stride);

#endif
