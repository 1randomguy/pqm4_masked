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
#include "masked_representations.h"
#include "gadgets.h"
#include "masked_utils.h"

/*************************************************
 * Name: transpose32
 *
 * Description: Transpose 32 x 32 bit matrix
 *
 * Arguments:
 * - uint32_t[32] a: the matrix, updated such that the new value of (a[i] >> j)
 *   & 0x1 is the initial value of (a[j] >> i) & 0x1.
 *
 * Adapted from "Hacker's Delight" by Henry S. Warren, Jr.
 * at http://www.icodeguru.com/Embedded/Hacker's-Delight/
 * **************************************************/

void transpose32(uint32_t a[32]) {
  int j, k;
  uint32_t m, t;
  m = 0x0000FFFF;
  for (j = 16; j != 0; j = j >> 1, m = m ^ (m << j)) {
    for (k = 0; k < 32; k = (k + j + 1) & ~j) {
      t = (a[k + j] ^ (a[k] >> j)) & m;
      a[k + j] = a[k + j] ^ t;
      a[k] = a[k] ^ (t << j);
    }
  }
}

void masked_dense2bitslice_opt_u32(
    size_t nshares, size_t coeffs_size, uint32_t *bitslice,
    size_t bitslice_msk_stride, size_t bitslice_data_stride,
    const uint32_t *dense, size_t dense_msk_stride, size_t dense_data_stride) {
  uint32_t a[32];
  for (size_t d = 0; d < nshares; d++) {
    for (size_t i = 0; i < 32; i++) {
      a[i] = dense[i * dense_data_stride + d * dense_msk_stride];
    }
    transpose32(a);
    for (size_t i = 0; i < coeffs_size; i++) {
      bitslice[d * bitslice_msk_stride + i * bitslice_data_stride] = a[i];
    }
  }
}

void masked_bitslice2dense_opt(size_t nshares, size_t coeffs_size,
                               int32_t *dense, size_t dense_msk_stride,
                               size_t dense_data_stride,
                               const uint32_t *bitslice,
                               size_t bitslice_msk_stride,
                               size_t bitslice_data_stride) {
  uint32_t a[32];
  for (size_t d = 0; d < nshares; d++) {
    for (size_t i = 0; i < coeffs_size; i++) {
      a[i] = bitslice[d * bitslice_msk_stride + i * bitslice_data_stride];
    }
    // Avoid uninitialized vars -> UB :(
    for (size_t i = coeffs_size; i < 32; i++) {
      a[i] = 0;
    }
    transpose32(a);
    for (size_t i = 0; i < 32; i++) {
      dense[d * dense_msk_stride + i * dense_data_stride] = a[i];
    }
  }
}

void seca2b_modp(size_t nshares, size_t kbits, uint32_t p, uint32_t *in,
                 size_t in_msk_stride, size_t in_data_stride) {

  size_t i, d;

  if (nshares == 1) {
    return;
  }

  size_t nshares_low = nshares / 2;
  size_t nshares_high = nshares - nshares_low;

  seca2b_modp(nshares_low, kbits, p, in, in_msk_stride, in_data_stride);
  seca2b_modp(nshares_high, kbits, p, &in[nshares_low * in_msk_stride],
              in_msk_stride, in_data_stride);

  uint32_t expanded_low[(kbits + 1) * nshares];
  uint32_t expanded_high[(kbits + 1) * nshares];
  uint32_t u[(kbits + 1) * nshares];

  secadd_constant(nshares_low, kbits, kbits + 1, expanded_low, 1, nshares, in,
                  in_msk_stride, in_data_stride, (1 << (kbits + 1)) - p);

  for (i = 0; i < (kbits + 1); i++) {
    if (i < kbits) {
      copy_sharing(nshares_high, &expanded_high[i * nshares + nshares_low], 1,
                   &in[i * in_data_stride + nshares_low * in_msk_stride],
                   in_msk_stride);
    }
    for (d = 0; d < nshares_low; d++) {
      // has already been written by secadd_constant_bmsk
      // expanded_low[i*nshares + d] = in[i*in_data_stride + d*in_msk_stride];
      expanded_high[i * nshares + d] = 0;
    }
    for (d = nshares_low; d < nshares; d++) {
      // kbits + 1 within in is unset
      if (i >= kbits) {
        expanded_high[i * nshares + d] = 0;
      }
      expanded_low[i * nshares + d] = 0;
    }
  }

  secadd(nshares, kbits + 1, kbits + 1, u, 1, nshares, expanded_high, 1,
         nshares, expanded_low, 1, nshares);

  secadd_constant_bmsk(nshares, kbits, kbits, in, in_msk_stride, in_data_stride,
                       u, 1, nshares, p, &u[kbits * nshares], 1);
}

void seca2b(size_t nshares, size_t kbits, uint32_t *in, size_t in_msk_stride,
            size_t in_data_stride) {

  size_t i, d;

  if (nshares == 1) {
    return;
  }

  size_t nshares_low = nshares / 2;
  size_t nshares_high = nshares - nshares_low;

  seca2b(nshares_low, kbits, in, in_msk_stride, in_data_stride);
  seca2b(nshares_high, kbits, &in[nshares_low * in_msk_stride], in_msk_stride,
         in_data_stride);

  uint32_t expanded_low[kbits * nshares];
  uint32_t expanded_high[kbits * nshares];

  for (i = 0; i < kbits; i++) {
    copy_sharing(nshares_low, &expanded_low[i * nshares], 1,
                 &in[i * in_data_stride], in_msk_stride);
    copy_sharing(nshares_high, &expanded_high[i * nshares + nshares_low], 1,
                 &in[i * in_data_stride + nshares_low * in_msk_stride],
                 in_msk_stride);

    for (d = 0; d < nshares_low; d++) {
      expanded_high[i * nshares + d] = 0;
    }
    for (d = nshares_low; d < nshares; d++) {
      expanded_low[i * nshares + d] = 0;
    }
  }

  secadd(nshares, kbits, kbits, in, in_msk_stride, in_data_stride, expanded_low,
         1, nshares, expanded_high, 1, nshares);
}

/*************************************************
 * Name:        secb2a_modp
 *
 * Description: Inplace boolean to arithmetic masking conversion:
 *            sum(in_i)%(p) = XOR(in_i)
 *
 * /!\ This function is operating on two slices such that 64 conversions are
 * performed in parallel.
 *
 * Arguments: - size_t nshares: number of shares
 *            - size_t kbits: number of bits in input words. kbits =
 *ceil(log(p))
 *            - uint32_t p: modulus of the arithmetic masking
 *            - uint32_t *in: input buffer
 *            - size_t in_msk_stride: stride between shares
 *            - size_t in_data_stride: stride between masked bits
 **************************************************/
void secb2a_modp(size_t nshares,
                 //   size_t kbits, // MUST BE EQUAL TO Q_BITS
                 uint32_t p, uint32_t *in, size_t in_msk_stride,
                 size_t in_data_stride) {

  uint32_t z_dense[BSSIZE * nshares];
  uint32_t zp_dense[BSSIZE * nshares];
  uint32_t zp_str[Q_BITS * nshares];
  uint32_t b_str[Q_BITS * nshares];
  int32_t r;
  size_t d, i;

  // generate uniform sharing for z
  // zp = p - z;
  for (i = 0; i < BSSIZE; i += 1) {
    for (d = 0; d < nshares - 1; d++) {
      r = get_randomq();
      z_dense[i * nshares + d] = r;
      zp_dense[i * nshares + d] = (p - r) % p;
    }
    z_dense[i * nshares + nshares - 1] = 0;
    zp_dense[i * nshares + nshares - 1] = 0;
  }

  // map zp to bitslice representation
  masked_dense2bitslice_opt_u32(nshares, Q_BITS, zp_str, 1, nshares, zp_dense,
                                1, nshares);

  // last shares of zp_str to zero
  seca2b_modp(nshares, Q_BITS, p, zp_str, 1, nshares);
  /*  for(int i = 0; i < Q_BITS * nshares; i++)
      zp_str[i] = 0;*/
  secadd_modp(nshares, Q_BITS, p, b_str, 1, nshares, in, in_msk_stride,
              in_data_stride, zp_str, 1, nshares);
  // map z to bistlice in output buffer
  masked_dense2bitslice_opt_u32(nshares, Q_BITS, in, in_msk_stride,
                                in_data_stride, z_dense, 1, nshares);

  // unmask b_str and set to the last share of the output
  for (i = 0; i < Q_BITS; i++) {
    refreshIOS(&b_str[i * nshares], 1);

    in[i * in_data_stride + (nshares - 1) * in_msk_stride] = 0;
    for (d = 0; d < nshares; d++) {
      in[i * in_data_stride + (nshares - 1) * in_msk_stride] ^=
          b_str[i * nshares + d];
    }
  }
}
