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
#include "masked_utils.h"
#include "masked.h"
#include "poly.h"
#include <libopencm3/stm32/rng.h>
#include <stdint.h>

extern inline uint32_t get_randomq();

#ifndef BENCH_RND
#define BENCH_RND 0
#endif

#if BENCH_RND == 1
extern uint64_t rng_cnt;
#endif

uint32_t get_random() {
#if BENCH_RND == 1
  rng_cnt += 1;
#endif
  while (1) {
    if ((RNG_SR & RNG_SR_DRDY) == 1) { // check if data is ready
      return RNG_DR;
    }
  }
  return 0;
}

void mask_poly(msk_poly *mp, const poly *p) {
  int32_t v;
  for (int i = 0; i < N; i++) {
    (*mp)[0].coeffs[i] = p->coeffs[i];
    for (int d = 1; d < NSHARES; d++) {
      v = get_randomq();
      (*mp)[0].coeffs[i] = ((*mp)[0].coeffs[i] + v) % Q;
      (*mp)[d].coeffs[i] = (Q - v) % Q;
      (*mp)[d].coeffs[i] -= (((*mp)[d].coeffs[i] > (Q / 2)) & 0x1) * Q;
    }
    (*mp)[0].coeffs[i] -= (((*mp)[0].coeffs[i] > (Q / 2)) & 0x1) * Q;
  }
}

void mask_polyvecl(msk_polyvecl *mpv, const polyvecl *pv) {
  for (int k = 0; k < L; k++) {
    mask_poly(*mpv + k, pv->vec + k);
  }
}

void mask_polyveck(msk_polyveck *mpv, const polyveck *pv) {
  for (int k = 0; k < K; k++) {
    mask_poly(*mpv + k, pv->vec + k);
  }
}

void unmask_poly(poly *p, const msk_poly *mp) {
  for (int i = 0; i < N; i++) {
    p->coeffs[i] = (*mp)[0].coeffs[i];
    for (int d = 1; d < NSHARES; d++) {
      p->coeffs[i] = (p->coeffs[i] + (*mp)[d].coeffs[i] + Q) % Q;
    }
    p->coeffs[i] -= ((p->coeffs[i] > (Q / 2)) & 0x1) * Q;
  }
}

void unmask_polyvecl(polyvecl *pv, const msk_polyvecl *mpv) {
  for (int k = 0; k < L; k++) {
    unmask_poly(pv->vec + k, *mpv + k);
  }
}

void unmask_polyveck(polyveck *pv, const msk_polyveck *mpv) {
  for (int k = 0; k < K; k++) {
    unmask_poly(pv->vec + k, *mpv + k);
  }
}

void smallpolyvec2polyvecl(polyvecl *pv, const smallpoly spv[]) {
  for (int k = 0; k < L; k++) {
    for (int i = 0; i < N; i++) {
      pv->vec[k].coeffs[i] = (int32_t)spv[k].coeffs[i];
    }
  }
}

void smallpolyvec2polyveck(polyveck *pv, const smallpoly spv[]) {
  for (int k = 0; k < K; k++) {
    for (int i = 0; i < N; i++) {
      pv->vec[k].coeffs[i] = spv[k].coeffs[i];
    }
  }
}

void mask_bytes(size_t n, uint8_t *out, size_t out_msk_stride,
                size_t out_data_stride, const uint8_t *in, size_t in_stride) {
  int32_t v;
  for (size_t i = 0; i < n; i++) {
    out[i * out_data_stride] = in[i * in_stride];
    for (int d = 1; d < NSHARES; d++) {
      v = get_random() & 0xFF;
      out[i * out_data_stride] ^= v;
      out[i * out_data_stride + d * out_msk_stride] = v;
    }
  }
}

void unmask_bytes(size_t n, uint8_t *out, size_t out_stride, const uint8_t *in,
                  size_t in_msk_stride, size_t in_data_stride) {
  for (size_t i = 0; i < n; i++) {
    out[i * out_stride] = in[i * in_data_stride];
    for (int d = 1; d < NSHARES; d++) {
      out[i * out_stride] ^= in[i * in_data_stride + d * in_msk_stride];
    }
  }
}
