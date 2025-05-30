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
#ifndef MASKED_UTILS_H
#define MASKED_UTILS_H
#include "hal.h"
#include "masked.h"
#include "poly.h"
#include "randombytes.h"
#include "smallpoly.h"
#include <stdint.h>

uint32_t get_random();

inline uint32_t get_randomq() {
  uint32_t r = get_random() & ((1 << 23) - 1); // GET 23 random bits
  while (r >= Q) {
    r = get_random() & ((1 << 23) - 1);
  }
  return r;
}

void mask_poly(msk_poly *mp, const poly *p);
void mask_polyvecl(msk_polyvecl *mpv, const polyvecl *pv);
void mask_polyveck(msk_polyveck *mpv, const polyveck *pv);
void unmask_poly(poly *p, const msk_poly *mp);
void unmask_polyvecl(polyvecl *p, const msk_polyvecl *mpv);
void unmask_polyveck(polyveck *p, const msk_polyveck *mpv);
void smallpolyvec2polyvecl(polyvecl *pv, const smallpoly spv[]);
void smallpolyvec2polyveck(polyveck *pv, const smallpoly spv[]);

void mask_bytes(size_t n, uint8_t *out, size_t out_msk_stride,
                size_t out_data_stride, const uint8_t *in, size_t in_stride

);
void unmask_bytes(size_t n, uint8_t *out, size_t out_stride, const uint8_t *in,
                  size_t in_msk_stride, size_t in_data_stride);
#endif
