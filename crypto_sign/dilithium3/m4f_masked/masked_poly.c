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
#include "masked_poly.h"
#include "gadgets.h"
#include "masked.h"
#include "masked_fips202.h"
#include "masked_representations.h"
#include "ntt.h"
#include "params.h"
#include "pointwise_mont.h"
#include "symmetric.h"
#include "vector.h"

#include "hal.h"
#include <stdio.h>

void msk_poly_reduce(msk_poly *a) {
  for (int d = 0; d < NSHARES; d++) {
    asm_reduce32((*a + d)->coeffs);
  }
}

void msk_poly_caddq(msk_poly *a) {
  for (int d = 0; d < NSHARES; d++) {
    poly_caddq(&(*a)[d]);
  }
}

void msk_poly_freeze(msk_poly *a) {
  for (int d = 0; d < NSHARES; d++) {
    poly_freeze(&(*a)[d]);
  }
}

void msk_poly_cp(msk_poly *a_cp, const msk_poly *a) {
  for (int d = 0; d < NSHARES; d++) {
    for (int i = 0; i < N; i++) {
      (*a_cp + d)->coeffs[i] = (*a + d)->coeffs[i];
    }
  }
}

void msk_poly_sub(msk_poly *c, const msk_poly *a, const msk_poly *b) {
  unsigned int i;
  for (int d = 0; d < NSHARES; d++) {
    for (i = 0; i < N; ++i) {
      (*c + d)->coeffs[i] = (*a + d)->coeffs[i] - (*b + d)->coeffs[i];
    }
  }
}

void msk_poly_invntt_tomont(msk_poly *a) {
  for (int d = 0; d < NSHARES; d++) {
    invntt_tomont((*a + d)->coeffs);
  }
}

void msk_poly_pointwise_montgomery(msk_poly *c, const poly *a,
                                   const msk_poly *b) {
  for (int d = 0; d < NSHARES; d++) {
    asm_pointwise_montgomery((*c + d)->coeffs, a->coeffs, (*b + d)->coeffs);
  }
}

int msk_poly_chknorm(const msk_poly *a, int32_t B) {
  msk_poly a_cp;
  uint32_t bitsliced[NSHARES * Q_BITS];
  uint32_t ret = 1;

  if (B > (Q - 1) / 8) {
    return 1;
  }
  B--;

  msk_poly_cp(&a_cp, a);
  for (int i = 0; i < N; i++) {
    a_cp->coeffs[i] = ((a_cp->coeffs[i] + B) % Q + Q) % Q;
  }
  msk_poly_freeze(&a_cp);

  for (int i = 0; i < N; i += 32) {
    masked_dense2bitslice_opt_u32(NSHARES, Q_BITS, bitsliced, 1, NSHARES,
                                  (uint32_t *)(a_cp->coeffs + i), N, 1);
    seca2b_modp(NSHARES, Q_BITS, Q, bitsliced, 1, NSHARES);
    ret &= secleq_constant(Q_BITS, bitsliced, 1, NSHARES, 2 * B);
  }
  return 1 - ret;
}

void msk_poly_decompose(poly *w1, msk_poly *msk_w0, const msk_poly *msk_w) {
  uint32_t bs[NSHARES * Q_BITS];

  for (int i = 0; i < N; i++) {
    (*msk_w0)[0].coeffs[i] =
        (((INV_ALPHA * ((int64_t)((*msk_w)[0].coeffs[i]) + GAMMA2)) - 1) % Q +
         Q) %
        Q;
    for (int d = 1; d < NSHARES; d++) {
      (*msk_w0)[d].coeffs[i] =
          (INV_ALPHA * (int64_t)(*msk_w)[d].coeffs[i] % Q + Q) % Q;
    }
  }

  for (int i = 0; i < N; i += 32) {
    masked_dense2bitslice_opt_u32(NSHARES, Q_BITS, bs, 1, NSHARES,
                                  (uint32_t *)((*msk_w0)->coeffs + i), N, 1);
    seca2b_modp(NSHARES, Q_BITS, Q, bs, 1, NSHARES);

    // Refresh 4 LSBs from bs coefficients, unmask and convert back to dense
    // from bitslice.
    uint32_t bs_w1[4];
    for (int j = 0; j < 4; j++) {
      refreshIOS(&bs[j * NSHARES], 1);
      bs_w1[j] = 0;
      for (int d = 0; d < NSHARES; d++) {
        bs_w1[j] ^= bs[j * NSHARES + d];
      }
    }
    masked_bitslice2dense_opt(1, 4, &w1->coeffs[i], 0, 1, bs_w1, 0, 1);

    for (int i0 = i; i0 < i + 32; i0++) {
      (*msk_w0)[0].coeffs[i0] =
          (((**msk_w).coeffs[i0] - ALPHA * w1->coeffs[i0]) % Q + Q) % Q;
      for (int d = 1; d < NSHARES; d++) {
        (*msk_w0)[d].coeffs[i0] = (*msk_w)[d].coeffs[i0];
      }
    }
  }
}

void unmask_bool_test(poly *x, const uint32_t bs_msk_x[NSHARES * Q_BITS]) {
  for (int i = 0; i < 32; i++) {
    x->coeffs[i] = 0;
  }
  for (int d = 0; d < NSHARES; d++) {
    for (int i = 0; i < 32; i++) {
      for (int b = 0; b < Q_BITS; b++) {
        x->coeffs[i] ^= ((bs_msk_x[b * NSHARES + d] >> i) & 0x1) << b;
      }
    }
  }
}

void unmask_arit_test(poly *x, const uint32_t bs_msk_x[NSHARES * Q_BITS]) {
  for (int i = 0; i < 32; i++) {
    x->coeffs[i] = 0;
  }
  for (int d = 0; d < NSHARES; d++) {
    for (int i = 0; i < 32; i++) {
      for (int b = 0; b < Q_BITS; b++) {
        x->coeffs[i] =
            (((x->coeffs[i] + (((bs_msk_x[b * NSHARES + d] >> i) & 0x1) << b)) %
              Q) +
             Q) %
            Q;
      }
    }
  }
}

void msk_poly_uniform_gamma1(msk_poly *msk_y,
                             const uint8_t seed[NSHARES * CRHBYTES],
                             uint16_t nonce) {
  uint32_t bs[NSHARES * Q_BITS];
  size_t nbytes = POLY_UNIFORM_GAMMA1_NBLOCKS * STREAM256_BLOCKBYTES;

  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  // We use a non-incremental API for hashing, which is simple but inefficient
  // regarding RAM usage (also, we do too many copies).
  uint8_t tmp_buf[NSHARES * (CRHBYTES + 2)];
  for (int d = 0; d < NSHARES; d++) {
    memcpy(tmp_buf + d * (CRHBYTES + 2), seed + d * CRHBYTES, CRHBYTES);
    memset(tmp_buf + d * (CRHBYTES + 2) + CRHBYTES, 0, 2);
  }
  memcpy(tmp_buf + CRHBYTES, t, 2);

  uint8_t buf[NSHARES * POLY_UNIFORM_GAMMA1_NBLOCKS * STREAM256_BLOCKBYTES];
  masked_shake256(buf, nbytes, nbytes, 1, tmp_buf, CRHBYTES + 2, CRHBYTES + 2,
                  1);

  for (int d = 0; d < NSHARES; d++) {
    polyz_unpack_positive((*msk_y) + d, buf + d * nbytes);
  }

  for (int i = 0; i < N; i += 32) {
    masked_dense2bitslice_opt_u32(NSHARES, Q_BITS, bs, 1, NSHARES,
                                  (uint32_t *)(*msk_y)->coeffs + i, N, 1);
    secb2a_modp(NSHARES, Q, bs, 1, NSHARES);

    masked_bitslice2dense_opt(NSHARES, Q_BITS,
                              (int32_t *)((*msk_y)->coeffs) + i, N, 1, bs, 1,
                              NSHARES);
  }
  for (int i = 0; i < N; i++) {
    (*msk_y)[0].coeffs[i] = GAMMA1 - (*msk_y)[0].coeffs[i];
    for (int d = 1; d < NSHARES; d++) {
      (*msk_y)[d].coeffs[i] *= -1;
    }
  }
}

void bs_polyz_unpack(uint32_t bs[NSHARES * Q_BITS], uint8_t *r) {
#if GAMMA1 == (1 << 17)
  // Not handled
#elif GAMMA1 == (1 << 19)
  for (int i = 0; i < NSHARES * (LOG_GAMMA1 + 1); i++) {
    bs[i] = r[4 * i];
    for (int k = 1; k < 4; k++) {
      bs[i] += r[4 * i + k] << (8 * k);
    }
  }
  for (int i = NSHARES * (LOG_GAMMA1 + 1); i < NSHARES * Q_BITS; i++) {
    bs[i] = 0;
  }
#endif
}
