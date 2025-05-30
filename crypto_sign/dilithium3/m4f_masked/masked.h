#ifndef MASKED_H
#define MASKED_H
#include "params.h"
#include "poly.h"
#include <stdint.h>
#include <stdio.h>

#ifndef NSHARES
#define NSHARES 2
#endif

typedef poly msk_poly[NSHARES];
typedef msk_poly msk_polyvecl[L];
typedef msk_poly msk_polyveck[K];

#define BAIL(...)                                                              \
  do {                                                                         \
    char bail_buf[100];                                                        \
    sprintf(bail_buf, __VA_ARGS__);                                            \
    hal_send_str(bail_buf);                                                    \
  } while (0);

#endif
