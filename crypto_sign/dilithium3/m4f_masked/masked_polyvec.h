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
#ifndef MASKED_POLYVEC_H
#define MASKED_POLYVEC_H

#include "masked.h"
#include "masked_utils.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include <stdint.h>

void msk_polyvec_matrix_pointwise_montgomery(msk_polyveck *msk_t,
                                             const polyvecl mat[K],
                                             const msk_polyvecl *msk_v);

void msk_polyvecl_reduce(msk_polyvecl *mpv);
void msk_polyvecl_add(msk_polyvecl *mpv_ret, const msk_polyvecl *mpv1,
                      const msk_polyvecl *mpv2);
void msk_polyvecl_ntt(msk_polyvecl *mpv);
void msk_polyvecl_invntt_tomont(msk_polyvecl *mpv);
void msk_polyvecl_pointwise_poly_montgomery(msk_polyvecl *msk_r, const poly *a,
                                            const msk_polyvecl *msk_v);
void msk_polyvecl_pointwise_acc_montgomery(msk_poly *msk_w, const polyvecl *u,
                                           const msk_polyvecl *msk_v);
void msk_polyvecl_uniform_gamma1(msk_polyvecl *y,
                                 const uint8_t seed[NSHARES * CRHBYTES],
                                 uint16_t nonce);

void msk_polyveck_reduce(msk_polyveck *mpv);
void msk_polyveck_caddq(msk_polyveck *mpv);
void msk_polyveck_ntt(msk_polyveck *mpv);
void msk_polyveck_invntt_tomont(msk_polyveck *mpv);
void msk_polyveck_decompose(polyveck *msk_w1, msk_polyveck *msk_w0,
                            const msk_polyveck *msk_w);
int msk_polyvecl_chknorm(msk_polyvecl *mpv, int32_t B);

void msk_polyvecl_cp(msk_polyvecl *msk_pv_cp, const msk_polyvecl *msk_pv);

#endif
