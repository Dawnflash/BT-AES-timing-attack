# AES timing attack

A bachelor thesis analyzing the timing side-channel for AES-128

The project has the form of a laboratory exercise for BI-HWB students (FIT CTU).\
The code blocks in `main.c` denoted by `/* REMOVE FOR STUDENTS */` should be removed prior to serving the project to students. \
The `truncated` branch has these blocks removed. \
See the [Laboratory assignment](#laboratory-assignment) section for details.

There are two segments: the encryption core `main.c` and analytic wrapper `analyze.py`.
You need to build the core first before running the wrapper.

The core itself plays two roles:
1. Gathering timing correlations and placing them in `corr.txt`
2. Brute-forcing the key

The wrapper runs the core in a loop, gathering, analyzing and summing the correlations the core outputs. It also backs up correlation data, visualizes the results using matplotlib and tries to automatically select candidates for each key byte position.

The candidates for a position are called a "pool". Pools smaller or equal to `max_pool_size` are displayed every time new data is tallied by the wrapper. Once enough data is leaked about the key, the wrapper invokes the core to brute-force it. This is dependent on your encryption rate. Tweak `max_seconds` to move the threshold.

The wrapper saves its progress continually in `cp_pools.txt` and `cp_data.txt`. These are human readable and editable if needed.

The graph outputs of the wrapper are read left to right, top to bottom, one graph for each byte of the key.

## Prerequisites
* python >= 3.6
* matplotlib (python module)
* openssl (libcrypto)

Linux:
* gcc (C compiler)
* GNU make

Windows:
* MSVC (C/++ compiler)


## How to build
This project uses make for building and other tasks.

Windows users should use the `NMAKE` tool from Visual Studio toolkit.
Invoke make as `nmake -f Makefile_win` from the VS development console.\
Users should read `Makefile` or `Makefile_win` depending on their OS and set the variables.

* Installing dependencies: `make depinstall`
* Building the project: `make`

## How to run
Useful make targets (invoke as `make TARGET`):
* `test`: clean up, generate a new key and run
* `gen`: generate a new AES key
* `all`: build and test
* `run`: run from the latest checkpoint, if any
* `clean`: remove checkpoints
* `show`: show graph of latest data
* `showcp`: show graph of latest checkpoint

Have a look at the `main.c` defines and `analyze.py` constants for tweaks.

Notable tweaks:
* `DEFAULT_RUNS` (core) number of encryptions per key (higher = slower but more accurate)
* `KEYS_CAP` (core) number of keys correlated against the target (higher = slower but more accurate)
* `THRESH_MULT` (core) repeat measurements which exceed this multiple of measured mean
* `PRIORITIZE_PROCESS` (core) prioritize core process (provides possibly more accurate results)
* `max_seconds` (wrapper) maximum seconds a brute-force attack should run
* `show_max` (wrapper) mark maxima on the graphs

The core requires a target key in the binary `aes.key` file if `RANDOMIZE_KEY` is off. \
Use `make gen` to generate one.

If the implementation seems resistant, try increasing `KEYS_CAP` to 20, alternatively increment `DEFAULT_RUNS`.\
To speed up the process you can try reducing `KEYS_CAP`.

If the wrapper seems unable to find any more data, kill the wrapper and check the checkpoint files for more info about each key byte.
You can manually edit the pools. \
Run `make showcp` and analyze the graphs.
Peak values tend to be good key candidates. Sometimes the wrapper misses or wrongly detects the candidates. Edit `cp_pools.txt` accordingly.

Sometimes not enough data can be acquired to break the key within reasonable time. Several bytes should always leak if the implementation is vulnerable, though.
**A resistant implementation should not leak any bytes**

Run `analyze.py -h` to see all wrapper options and usage.

Tip: the core prints the target key every time it takes measurements with it (look for `0. key` in the output). Check the pools the wrapper outputs and compare them with the actual key bytes. Correct pools tend to share several bits. The shared bits are almost 100% correct. You can use this when pinpointing correct candidates.

## Testing against custom implementation
1. Set `USE_OPENSSL` to 0 in the Makefile
2. Include and implement the `aes.h` header in your implementation. The expanded key should be a static state set by `aes_expand`
3. Set the `OWN_IMPLEMENTATION` variable in the build script to your implementation. Note: add any additional flags needed (e.g. `-maes`)
4. Build the project

## Testing against system OpenSSL
1. (Makefile) Set `USE_OPENSSL` to 1
2. (Windows Makefile) Set `OPENSSL_PATH` to "lib"
3. Build the project

## Testing against custom OpenSSL
1. (Makefile) Set `USE_OPENSSL` to 1
2. (Makefile) Set `OPENSSL_PATH` to the extracted OpenSSL directory
3. (Windows Makefile) Clear `OPENSSL_LIBPATH`
4. Build OpenSSL (follow the `INSTALL` file), try the `no-asm` configuration which is vulnerable on some hardware
5. Build the project. Linux note: When running the software directly (not using `make` targets), set `LD_LIBRARY_PATH` to the OpenSSL directory

## Attack explanation

The first round in a T-box optimized AES implementation uses the initial state as index to the T-boxes. The initial state is a bitwise XOR of the input block (`n`) and the key (`k`).

If we assume array accesses to be time-dependent on index (which seems to be the case), then we can draw correlations between encryption time and `k ^ n`.

By generating a large number of random blocks and encrypting them with our unknown key we gather `n` and time but we lack the key `k1`.

However, if we can test an arbitrary number of encryptions with randomly generated keys `k2` on the same system, we will know both `n ^ k2` and the time. For each such `n ^ k2` we can test all possible values of unknown `k1` and correlate `n ^ k2` with `n ^ k1`.
The values of `k1` which correlate the best are the most likely key candidates.

We can perform this analysis for all 16 bytes of `k1` and by performing multiple measurements we can attempt to leak enough of `k1` to brute-force it within reasonable time.

## Laboratory assignment
### Core task
Test your AES-128 implementations for timing side-channel attack vulnerability. \
Note: it is not necessary to completely break every key. Even leaking several of its bytes signifies a severe vulnerability.
1. Complete the core module (`main.c`). There are three missing code blocks denoted by `TODO` comment blocks: tallying, calculating means and correlating.
Read the [Attack explanation](#attack-explanation) section to understand what's going on
2. Follow the [Testing against custom implementation](#testing-against-custom-implementation) section to build the project. Do this for all AES implementations you have
3. Run it for each implementation and check the results. Read [How to run](#how-to-run) for tips

Expected results: only the T-BOX implementation should be vulnerable

### Optional task
Test OpenSSL for the same vulnerability. The default system-wide installations of OpenSSL (libcrypto) are compiled with hardware encryption support.
1. Follow the [Testing against system OpenSSL](#testing-against-system-openssl) section for guidelines to build the project against a system-default OpenSSL.
2. Run it for a and check the results. Read [How to run](#how-to-run) for tips.
3. Compare it with your AES-NI implementation. Which one is faster?
4. Follow the [Testing against custom OpenSSL](#testing-against-custom-openssl) section for guidelines to build the project against a build configured with the `no-asm` option.
 Hint: see [How to run](#how-to-run) if the implementation seems resistant. On some systems it simply won't work.
5. Compare its vulnerability with the default/system build.


Expected results: system OpenSSL should be resistant, `no-asm` build should not but I have found cases when it didn't work...

### Further curiosities
1. Try turning off ASLR (Linux: `echo 0 >/proc/sys/kernel/randomize_va_space`) and see how it affects the attack. Run the wrapper with `-f` to see the effect
2. Lower optimization level (`OPTIMIZE`) to 1 and see how compiler optimizations affect the attack
