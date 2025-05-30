#include "sign.h"
#include "masked.h"
#include "masked_fips202.h"
#include "masked_poly.h"
#include "masked_polyvec.h"
#include "masked_utils.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "smallpoly.h"
#include "symmetric.h"
#include <stdint.h>

#define MASKED 0

/*************************************************
 * Name:        crypto_sign_keypair
 *
 * Description: Generates public and private key.
 *
 * Arguments:   - uint8_t *pk: pointer to output public key (allocated
 *                             array of CRYPTO_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output private key (allocated
 *                             array of CRYPTO_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
  uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
  uint8_t tr[SEEDBYTES];
  const uint8_t *rho, *rhoprime, *key;
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  /* Get randomness for rho, rhoprime and key */
  randombytes(seedbuf, SEEDBYTES);
  shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES);
  rho = seedbuf;
  rhoprime = rho + SEEDBYTES;
  key = rhoprime + CRHBYTES;

  /* Expand matrix */
  polyvec_matrix_expand(mat, rho);

  /* Sample short vectors s1 and s2 */
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, L);

  /* Matrix-vector multiplication */
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);

  /* Add error vector s2 */
  polyveck_add(&t1, &t1, &s2);

  /* Extract t1 and write public key */
  polyveck_caddq(&t1);
  polyveck_power2round(&t1, &t0, &t1);
  pack_pk(pk, rho, &t1);

  /* Compute H(rho, t1) and write secret key */
  shake256(tr, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

  return 0;
}
/*************************************************
 * Name:        crypto_sign_signature
 *
 * Description: Computes signature.
 *
 * Arguments:   - uint8_t *sig:   pointer to output signature (of length
 *CRYPTO_BYTES)
 *              - size_t *siglen: pointer to output length of signature
 *              - uint8_t *m:     pointer to message to be signed
 *              - size_t mlen:    length of message
 *              - uint8_t *sk:    pointer to bit-packed secret key
 *
 * Returns 0 (success)
 **************************************************/
int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                          size_t mlen, const uint8_t *sk) {
  uint8_t seedbuf[3 * SEEDBYTES + CRHBYTES];
  uint8_t *rho, *tr, *key, *mu;
  uint16_t nonce = 0;
  polyvecl mat[K], z;
  // msk_polyvecl msk_y;
  polyveck t0, w1, w0;
  poly cp;
  shake256incctx state;

  smallpoly s1_prime[L];
  smallpoly s2_prime[K];
  smallpoly cp_small;
  smallhalfpoly cp_small_prime;

  msk_polyvecl msk_s1_prime;
  msk_polyveck msk_s2_prime;

  /* Key decapsulation (non-masked) */
  // The key should be stored in masked form. This is not done in this example
  // code, for the sake of preserving compatibility with PQM4 API.
  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + SEEDBYTES;
  mu = key + SEEDBYTES;
  unpack_sk(rho, tr, key, &t0, s1_prime, s2_prime, sk);

  polyvecl s1_prime_big;
  polyveck s2_prime_big;
  smallpolyvec2polyvecl(&s1_prime_big, s1_prime);
  smallpolyvec2polyveck(&s2_prime_big, s2_prime);
  mask_polyvecl(&msk_s1_prime, &s1_prime_big);
  mask_polyveck(&msk_s2_prime, &s2_prime_big);

  // We only need key to be masked, not mu. However, we keep the two together
  // and mask both of them for the sake of simplicity in SHAKE..
  // Here we initialize the "key" part of keymu.
  uint8_t msk_keymu[NSHARES * (SEEDBYTES + CRHBYTES)];
  mask_bytes(SEEDBYTES, msk_keymu, SEEDBYTES + CRHBYTES, 1, key, 1);

  /* Compute CRH(tr, msg) */
  // Does not need to be masked (tr is public).
  shake256_inc_init(&state);
  shake256_inc_absorb(&state, tr, SEEDBYTES);
  shake256_inc_absorb(&state, m, mlen);
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(mu, CRHBYTES, &state);

  // Initialize "mu" part of keymu, (it is not necessary to mask it, but it does
  // not hurt).
  mask_bytes(CRHBYTES, msk_keymu + SEEDBYTES, SEEDBYTES + CRHBYTES, 1, mu, 1);

  uint8_t msk_rhoprime[NSHARES * CRHBYTES];
#ifdef DILITHIUM_RANDOMIZED_SIGNING
  randombytes(rhoprime, CRHBYTES);
  mask_bytes(CRHBYTES, msk_rhoprime, CRHBYTES, 1, rhoprime, 1);
#else
  masked_shake256(msk_rhoprime, CRHBYTES, CRHBYTES, 1, msk_keymu,
                  SEEDBYTES + CRHBYTES, SEEDBYTES + CRHBYTES, 1);
#endif

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  msk_polyvecl_ntt(&msk_s1_prime);
  msk_polyveck_ntt(&msk_s2_prime);

  // No need to mask, because its in the public key
  polyveck_ntt(&t0);

  msk_polyvecl msk_y;

// This is only for benchmarks, will make the algorithm incorrect (hence
// insecure).
#ifdef NEVER_REJECT
#define GOTOREJ                                                                \
  do {                                                                         \
    asm volatile(";" :::);                                                     \
  } while (0)
#else
#define GOTOREJ                                                                \
  do {                                                                         \
    goto rej;                                                                  \
  } while (0)
#endif
rej:
  /* Sample intermediate vector y */
  msk_polyvecl_uniform_gamma1(&msk_y, msk_rhoprime, nonce);
  nonce += 1;

  /* Matrix-vector multiplication */
  msk_polyvecl msk_z;
  msk_polyveck msk_w;

  msk_polyvecl_cp(&msk_z, &msk_y);
  msk_polyvecl_ntt(&msk_z);
  msk_polyvec_matrix_pointwise_montgomery(&msk_w, mat, &msk_z);
  msk_polyveck_reduce(&msk_w);
  msk_polyveck_invntt_tomont(&msk_w);

  /* Decompose w and call the random oracle */
  msk_polyveck_caddq(&msk_w);
  msk_polyveck msk_w0;
  msk_polyveck_decompose(&w1, &msk_w0, &msk_w);

  polyveck_pack_w1(sig, &w1);

  shake256_inc_init(&state);
  shake256_inc_absorb(&state, mu, CRHBYTES);
  shake256_inc_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(sig, SEEDBYTES, &state);
  poly_challenge(&cp, sig);

  poly_small_ntt_precomp(&cp_small, &cp_small_prime, &cp);
  poly_ntt(&cp);

  /* Compute z, reject if it reveals secret */
  msk_polyvecl_pointwise_poly_montgomery(&msk_z, &cp, &msk_s1_prime);
  msk_polyvecl_invntt_tomont(&msk_z);
  msk_polyvecl_add(&msk_z, &msk_z, &msk_y);
  msk_polyvecl_reduce(&msk_z); // limits the range of z.

  if (msk_polyvecl_chknorm(&msk_z, GAMMA1 - BETA)) {
    GOTOREJ;
  }

  // At this point, we can unmask z.
  unmask_polyvecl(&z, &msk_z);

  /* Write signature */
  pack_sig_z(sig, &z);
  unsigned int hint_n = 0;
  unsigned int hints_written = 0;
  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  for (unsigned int i = 0; i < K; ++i) {
    poly *tmp = &z.vec[0];
    msk_poly *msk_tmp = msk_z;

    msk_poly_pointwise_montgomery(msk_tmp, &cp, msk_s2_prime + i);
    msk_poly_invntt_tomont(msk_tmp);
    msk_poly_sub(msk_w0 + i, msk_w0 + i, msk_tmp);
    msk_poly_reduce(msk_w0 + i);

    if (msk_poly_chknorm(msk_w0 + i, GAMMA2 - BETA)) {
      GOTOREJ;
    }

    /* Compute hints for w1 */
    unmask_poly(&(w0.vec[i]), msk_w0 + i);
    unmask_poly(tmp, msk_tmp);
    poly_pointwise_montgomery(tmp, &cp, &t0.vec[i]);

    poly_invntt_tomont(tmp);
    poly_reduce(tmp);

    if (poly_chknorm(tmp, GAMMA2)) {
      GOTOREJ;
    }
    poly_add(&w0.vec[i], &w0.vec[i], tmp);
    hint_n += poly_make_hint(tmp, &w0.vec[i], &w1.vec[i]);
    if (hint_n > OMEGA) {
      GOTOREJ;
    }
    pack_sig_h(sig, tmp, i, &hints_written);
  }
  pack_sig_h_zero(sig, &hints_written);
  *siglen = CRYPTO_BYTES;
  return 0;
}

/*************************************************
 * Name:        crypto_sign
 *
 * Description: Compute signed message.
 *
 * Arguments:   - uint8_t *sm: pointer to output signed message (allocated
 *                             array with CRYPTO_BYTES + mlen bytes),
 *                             can be equal to m
 *              - size_t *smlen: pointer to output length of signed
 *                               message
 *              - const uint8_t *m: pointer to message to be signed
 *              - size_t mlen: length of message
 *              - const uint8_t *sk: pointer to bit-packed secret key
 *
 * Returns 0 (success)
 **************************************************/
int crypto_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
                const uint8_t *sk) {
  size_t i;

  for (i = 0; i < mlen; ++i)
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, sk);
  *smlen += mlen;
  return 0;
}

/*************************************************
 * Name:        crypto_sign_verify
 *
 * Description: Verifies signature.
 *
 * Arguments:   - uint8_t *m: pointer to input signature
 *              - size_t siglen: length of signature
 *              - const uint8_t *m: pointer to message
 *              - size_t mlen: length of message
 *              - const uint8_t *pk: pointer to bit-packed public key
 *
 * Returns 0 if signature could be verified correctly and -1 otherwise
 **************************************************/
int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                       size_t mlen, const uint8_t *pk) {
  unsigned int i;
  uint8_t buf[K * POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[SEEDBYTES];
  uint8_t c2[SEEDBYTES];
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, h;
  shake256incctx state;

  if (siglen != CRYPTO_BYTES)
    return -1;

  unpack_pk(rho, &t1, pk);
  if (unpack_sig(c, &z, &h, sig))
    return -1;
  if (polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;

  /* Compute CRH(h(rho, t1), msg) */
  shake256(mu, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_inc_init(&state);
  shake256_inc_absorb(&state, mu, SEEDBYTES);
  shake256_inc_absorb(&state, m, mlen);
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(mu, CRHBYTES, &state);

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);
  polyveck_pack_w1(buf, &w1);

  /* Call random oracle and verify challenge */
  shake256_inc_init(&state);
  shake256_inc_absorb(&state, mu, CRHBYTES);
  shake256_inc_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(c2, SEEDBYTES, &state);
  for (i = 0; i < SEEDBYTES; ++i)
    if (c[i] != c2[i])
      return -1;

  return 0;
}

/*************************************************
 * Name:        crypto_sign_open
 *
 * Description: Verify signed message.
 *
 * Arguments:   - uint8_t *m: pointer to output message (allocated
 *                            array with smlen bytes), can be equal to sm
 *              - size_t *mlen: pointer to output length of message
 *              - const uint8_t *sm: pointer to signed message
 *              - size_t smlen: length of signed message
 *              - const uint8_t *pk: pointer to bit-packed public key
 *
 * Returns 0 if signed message could be verified correctly and -1 otherwise
 **************************************************/
int crypto_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen,
                     const uint8_t *pk) {
  size_t i;

  if (smlen < CRYPTO_BYTES)
    goto badsig;

  *mlen = smlen - CRYPTO_BYTES;
  if (crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk))
    goto badsig;
  else {
    /* All good, copy msg, return 0 */
    for (i = 0; i < *mlen; ++i)
      m[i] = sm[CRYPTO_BYTES + i];
    return 0;
  }

badsig:
  /* Signature verification failed */
  *mlen = -1;
  for (i = 0; i < smlen; ++i)
    m[i] = 0;

  return -1;
}
