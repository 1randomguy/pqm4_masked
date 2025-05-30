# pqm4_masked

Post-quantum masked crypto library for the ARM Cortex-M4 based on [pqm4](https://github.com/mupq/pqm4).

## Introduction

The **pqm4\_masked** library is based on [pqm4](https://github.com/mupq/pqm4) and adds masked implementations of selected algorithms.
These implementations are intended as reference code, demonstrating how the algorithms can be masked.

**/!\\These implementations have not been subjected to leakage assessment nor to formal verification, and are therefore likely to have weaknesses./!\\**

Implemented algorithms:

- KEM ([research paper](https://tches.iacr.org/index.php/TCHES/article/view/9831))
  - `kyber768` (v3.02)
  - saber (round 3)
- Signature ([research paper](https://tches.iacr.org/index.php/TCHES/article/view/11158))
  - `dilithium3` (v3.1)

Differences from research papers:

- Fix weaknesses identified by [Zeitschner et al.](https://eprint.iacr.org/2023/034).
- Fresh re-implementation of dilithium.

For the version evaluated in the [first paper](https://tches.iacr.org/index.php/TCHES/article/view/9831), see the `tches` tag.

This code has not been optimized. Simple programming tricks can improve the
performances, especially for small number of shares.

See the code at:

- `crypto_kem/kyber768/m4fspeed_masked`
- `crypto_kem/saber/m4fspeed_masked`
- `crypto_sign/dilithium3/m4f_masked`

## Setup/Installation

Same as [pqm4](https://github.com/mupq/pqm4).

## API documentation

For the purpose of simple testing and benchmarking, the **pqm4\_masked**
library uses the NIST/SUPERCOP/[PQClean
API](https://github.com/PQClean/PQClean).
(See [pqm4](https://github.com/mupq/pqm4).)

**/!\\As a result, the secret key is stored unmasked, which is insecure./!\\**

**/!\\The epheremal (encapsulated) key is also unprotected similarly as [this paper](https://tches.iacr.org/index.php/TCHES/article/view/9064)./!\\**

## Running tests and benchmarks

`pqm4_masked` has been tested exclusively on the `nucleo-l4r5zi` target.

In addition to pqm4 common testing (`testvectors.py` and benchmarking `benchmarking.py`), `pqm4_masked` supports:

- testing a single implementation (e.g. `kyber768/m4fspeed_masked` as command-line parameter)
- benchmarking components of the masked implementation `subspeed` in `benchmarks.py`

### Example usages

Before running any code, run `cd libopencm3; make; cd ..`, otherwise the scripts fail.

```shell
# Testvectors
CFLAGS="-DNSHARES=2" python3 testvectors.py -p nucleo-l4r5zi --uart /dev/ttyACM0 kyber768/m4fspeed_masked
# Benchmark whole
CFLAGS="-DNSHARES=2 -DBENCH=0" python3 benchmarks.py -p nucleo-l4r5zi --uart /dev/ttyACM0 kyber768/m4fspeed_masked --speed
# Benchmark components
CFLAGS="-DNSHARES=2 -DBENCH=1" python3 benchmarks.py -p nucleo-l4r5zi --uart /dev/ttyACM0 kyber768/m4fspeed_masked --subspeed
```

(Replace `kyber768/m4fspeed_masked` with `saber/m4fspeed_masked` or `dilithium3/m4f_masked` for the other algorithms.)

By default, the implementations use a mix of C and Assembly (implementation
`S3` and `K3` in the research paper). In order to enforce the usage of pure C
implementation, the `CFLAGS` must contain `-DUSEC`. With the `USEC` defined,
the implementations `S2` and `K2` are used.

### Benchmarks

You can run all the benchmarks for `saber` or `kyber768`, then show a plot of
the results by runing:

```shell
./run_bench.sh kyber768 
python3 parse_bench.py kyber768 asm
python3 parse_bench.py kyber768 c
```

### Profiling framework

We provide a profiling framework that measures the execution time of
sub-parts of the implementations.
To configure the measured parts, first edit `BENCH_CASES` in
`common/bench.h` (we provide a reasonable default).

Example (to measure `my_function` and `my_other_function`):

```c
#define BENCH_CASES X(my_function) X(my_other_function)
```

Then you increase the performance counter of that part where it is called:

```c
start_bench(my_function);
my_function(...); // This can be any block of code you want to measure.
stop_bench(my_function);
```

See also `common/bench.c` and `common/speed_sub.c` for additional details about
the profiling framework.

Note that the profiling framework can be configured with `define`s (e.g. using
`CFLAGS` configuration).
To activate the profiling framework, the flag `BENCH=1` must be defined.
In order to measure randomness usage instead of cycle count, `BENCH_RND=1` must be defined.

## Bibliography

When referring to this framework in academic literature, please consider using the following bibTeX excerpts:

```
@article{DBLP:journals/tches/BronchainC22,
  author       = {Olivier Bronchain and
                  Ga{\"{e}}tan Cassiers},
  title        = {Bitslicing Arithmetic/Boolean Masking Conversions for Fun and Profit
                  with Application to Lattice-Based KEMs},
  journal      = {{IACR} Trans. Cryptogr. Hardw. Embed. Syst.},
  volume       = {2022},
  number       = {4},
  pages        = {553--588},
  year         = {2022}
}
@article{DBLP:journals/tches/AzouaouiBCHKRSSSV23,
  author       = {Melissa Azouaoui and
                  Olivier Bronchain and
                  Ga{\"{e}}tan Cassiers and
                  Cl{\'{e}}ment Hoffmann and
                  Yulia Kuzovkova and
                  Joost Renes and
                  Tobias Schneider and
                  Markus Sch{\"{o}}nauer and
                  Fran{\c{c}}ois{-}Xavier Standaert and
                  Christine van Vredendaal},
  title        = {Protecting Dilithium against Leakage Revisited Sensitivity Analysis
                  and Improved Implementations},
  journal      = {{IACR} Trans. Cryptogr. Hardw. Embed. Syst.},
  volume       = {2023},
  number       = {4},
  pages        = {58--79},
  year         = {2023}
}
```

## License

Different parts of **pqm4\_masked** have different licenses.
Each subdirectory containing implementations contains a LICENSE or COPYING file stating
under what license that specific implementation is released.
The files in common contain licensing information at the top of the file (and
are currently either public domain or MIT).
All other code in this repository is released under the conditions of [CC0](https://creativecommons.org/publicdomain/zero/1.0/).

Note: masked implementations are released under the conditions of the
[GPLv3](https://www.gnu.org/licenses/gpl-3.0.txt).
