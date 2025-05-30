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
#ifndef MASKED_POLY_H
#define MASKED_POLY_H

#include "masked.h"
#include "params.h"
#include <stdint.h>

#include "ntt.h"
#include "pointwise_mont.h"
#include "rounding.h"
#include "symmetric.h"
#include "vector.h"

#include "hal.h"
#include <stdio.h>

void msk_poly_reduce(msk_poly *a);
void msk_poly_freeze(msk_poly *a);
void msk_poly_cp(msk_poly *a_cp, const msk_poly *a);
void msk_poly_sub(msk_poly *c, const msk_poly *a, const msk_poly *b);
void msk_poly_invntt_tomont(msk_poly *a);
void msk_poly_pointwise_montgomery(msk_poly *c, const poly *a,
                                   const msk_poly *b);
int msk_poly_chknorm(const msk_poly *a, int32_t B);
void msk_poly_decompose(poly *w1, msk_poly *msk_w0, const msk_poly *msk_w);
void msk_poly_uniform_gamma1(msk_poly *y,
                             const uint8_t seed[NSHARES * CRHBYTES],
                             uint16_t nonce);
void bs_polyz_unpack(uint32_t bs[NSHARES * Q_BITS], uint8_t *r);

#endif
