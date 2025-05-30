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
#include "masked_polyvec.h"
#include "masked_poly.h"
#include "params.h"
#include "poly.h"

void msk_polyvec_matrix_pointwise_montgomery(msk_polyveck *msk_t,
                                             const polyvecl mat[K],
                                             const msk_polyvecl *msk_v) {
  for (int k = 0; k < K; k++) {
    msk_polyvecl_pointwise_acc_montgomery(&(*msk_t)[k], &mat[k], msk_v);
  }
}

void msk_polyvecl_reduce(msk_polyvecl *mpv) {
  for (int k = 0; k < L; k++) {
    for (int d = 0; d < NSHARES; d++) {
      poly_reduce(&(*mpv)[k][d]);
    }
  }
}

void msk_polyvecl_add(msk_polyvecl *mpv_ret, const msk_polyvecl *mpv1,
                      const msk_polyvecl *mpv2) {
  for (int k = 0; k < L; k++) {
    for (int d = 0; d < NSHARES; d++) {
      poly_add(&(*mpv_ret)[k][d], &(*mpv1)[k][d], &(*mpv2)[k][d]);
    }
  }
}

void msk_polyvecl_ntt(msk_polyvecl *mpv) {
  for (int k = 0; k < L; k++) {
    for (int d = 0; d < NSHARES; d++) {
      poly_ntt(&(*mpv)[k][d]);
    }
  }
}

void msk_polyvecl_invntt_tomont(msk_polyvecl *mpv) {
  for (int k = 0; k < L; k++) {
    for (int d = 0; d < NSHARES; d++) {
      poly_invntt_tomont(&(*mpv)[k][d]);
    }
  }
}

void msk_polyvecl_pointwise_poly_montgomery(msk_polyvecl *msk_r, const poly *a,
                                            const msk_polyvecl *msk_v) {
  for (int k = 0; k < L; k++) {
    for (int d = 0; d < NSHARES; d++) {
      poly_pointwise_montgomery(&(*msk_r)[k][d], a, &(*msk_v)[k][d]);
    }
  }
}

void msk_polyvecl_pointwise_acc_montgomery(msk_poly *msk_w, const polyvecl *u,
                                           const msk_polyvecl *msk_v) {
  for (int d = 0; d < NSHARES; d++) {
    poly_pointwise_montgomery(&(*msk_w)[d], &u->vec[0], &(*msk_v)[0][d]);
    for (int k = 1; k < L; k++) {
      poly_pointwise_acc_montgomery(&(*msk_w)[d], &u->vec[k], &(*msk_v)[k][d]);
    }
  }
}

int msk_polyvecl_chknorm(msk_polyvecl *mpv, int32_t B) {
  for (int k = 0; k < L; k++) {
    if (msk_poly_chknorm(&(*mpv)[k], B) == 1) {
      return 1;
    }
  }
  return 0;
}

void msk_polyvecl_uniform_gamma1(msk_polyvecl *y,
                                 const uint8_t seed[NSHARES * CRHBYTES],
                                 uint16_t nonce) {
  for (int k = 0; k < L; k++) {
    msk_poly_uniform_gamma1(&(*y)[k], seed, L * nonce + k);
  }
}

void msk_polyveck_reduce(msk_polyveck *mpv) {
  for (int k = 0; k < K; k++) {
    for (int d = 0; d < NSHARES; d++) {
      poly_reduce(&(*mpv)[k][d]);
    }
  }
}

void msk_polyveck_caddq(msk_polyveck *mpv) {
  for (int k = 0; k < K; k++) {
    for (int d = 0; d < NSHARES; d++) {
      poly_caddq(&(*mpv)[k][d]);
    }
  }
}

void msk_polyveck_ntt(msk_polyveck *mpv) {
  for (int k = 0; k < K; k++) {
    for (int d = 0; d < NSHARES; d++) {
      poly_ntt(&(*mpv)[k][d]);
    }
  }
}

void msk_polyveck_invntt_tomont(msk_polyveck *mpv) {
  for (int k = 0; k < K; k++) {
    for (int d = 0; d < NSHARES; d++) {
      poly_invntt_tomont(&(*mpv)[k][d]);
    }
  }
}

void msk_polyveck_decompose(polyveck *msk_w1, msk_polyveck *msk_w0,
                            const msk_polyveck *msk_w) {
  for (int k = 0; k < K; k++) {
    msk_poly_decompose(&msk_w1->vec[k], &(*msk_w0)[k], &(*msk_w)[k]);
  }
}

void msk_polyvecl_cp(msk_polyvecl *msk_pv_cp, const msk_polyvecl *msk_pv) {
  for (int k = 0; k < L; k++) {
    for (int d = 0; d < NSHARES; d++) {
      for (int i = 0; i < N; i++) {
        (*msk_pv_cp)[k][d].coeffs[i] = (*msk_pv)[k][d].coeffs[i];
      }
    }
  }
}
