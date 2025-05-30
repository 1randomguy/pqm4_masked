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
#ifndef MASKED_REPRESENTATIONS_H
#define MASKED_REPRESENTATIONS_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "gadgets.h"

void masked_dense2bitslice_opt_u32(
    size_t nshares, size_t coeffs_size, uint32_t *bitslice,
    size_t bitslice_msk_stride, size_t bitslice_data_stride,
    const uint32_t *dense, size_t dense_msk_stride, size_t dense_data_stride);


void masked_bitslice2dense_opt(size_t nshares, size_t coeffs_size,
                               int32_t *dense, size_t dense_msk_stride,
                               size_t dense_data_stide,
                               const uint32_t *bitslice,
                               size_t bitslice_msk_stride,
                               size_t bitslice_data_stride);


void seca2b_modp(size_t nshares, size_t kbits, uint32_t p, uint32_t *in,
                 size_t in_msk_stride, size_t in_data_stride);

void seca2b(size_t nshares, size_t kbits, uint32_t *in, size_t in_msk_stride,
            size_t in_data_stride);

void secb2a_modp(size_t nshares,
                 //   size_t kbits, // MUST BE EQUAL TO COEF_NBITS
                 uint32_t p, uint32_t *in, size_t in_msk_stride,
                 size_t in_data_stride);

void copy_sharing(size_t nshares, uint32_t *out, size_t out_stride,
                  const uint32_t *in, size_t in_stride);

#endif

