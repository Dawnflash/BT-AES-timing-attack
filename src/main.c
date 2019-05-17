/*
 * Created by Adam Zahumensky <zahumada@fit.cvut.cz> as part of a bachelor thesis on timing side-channel attacks on AES-128 (2019)
 *
 * This file serves as the encryption and measurement core, performing all encryption-related operations
 * The user may provide their own AES-128 implementation which must implement the "aes.h" header and be compiled with this file
 * Alternatively the user may test an OpenSSL implementation. See the Makefile(_win) for info on using OpenSSL
 * The core is meant to be run inside the provided python wrapper. This way, all produced files will be automatically analyzed.
 */

#define _GNU_SOURCE

#define DEFAULT_RUNS 22 // 2^DEFAULT_RUNS encryptions are done per key
#define THRESH_ON 1 // enable or disable threshold cutoff
#define THRESH_MULT 5 // multiplier of measured ticks average to discard as excessive
#define PURGE_CACHE 0 // purge cache after every encryption (massive performance penalty)
#define RAW_OUTPUT_ASCII 1 // output raw data in ASCII instead of binary format
#define KEYS_CAP 10 // try this many keys against the template
#define RANDOMIZE_KEY 0 // generate a random secret key if 1, else read one from fkey_name
#define OPENSSL_RAND 0 // use RAND_bytes from openssl instead of rand() WARNING: this negatively impacts performance
#define PREEMPTIVE_KEYEXPAND 1 // Expand AES key separately from individual encryption (this should stay on)

// lock process to a core and try to raise its priority
// this could be helpful if context switches are generating too much noise
#define PRIORITIZE_PROCESS 0

// 0 = minimum info displayed
// 1 = produce per-key correlations in corr$KEY_NO.txt and print analyses
// 2 = produce per-key tallies in tally$KEY_NO.txt
// 3 = produce raw dump in fraw_name
#define VERBOSE 0
// 0 = off
// 1 = leak secret information to correlation files
#define DEBUG 0

// returns integral time difference in nanoseconds (UNIX)
#define TIME_DIFF(start, end) (1000000000 * ((end.tv_sec) - (start.tv_sec)) + (end.tv_nsec) - (start.tv_nsec))
// returns floating time difference in seconds (Windows)
#define W_TIME_DIFF ((double) (time_end.QuadPart - time_start.QuadPart) / time_freq.QuadPart)

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <assert.h>
#include <string.h>
#include "aes.h"

#ifdef USE_OPENSSL
#include <openssl/aes.h>
#include <openssl/rand.h>
#endif

#ifdef _MSC_VER
#include <intrin.h>
#include <windows.h>
#else
#include <sched.h>
#include <unistd.h>
#include <x86intrin.h>
#endif

typedef uint8_t byte;

const char *fraw_name = "raw.dmp";
const char *fkey_name = "aes.key";
const char *frate_name = "enc_rate.txt";
const char *bf_name = "bf.dat";

byte *CACHE;
size_t CACHE_SIZE;

// expanded key for OpenSSL
#ifdef USE_OPENSSL
AES_KEY expanded_key;
#endif
// currently used key
byte *current_key;
// trash can for encrypted data
byte encdata[16];
// key to crack
byte target_key[16];
// cutoff threshold for encryption time
int tally_threshold = INT32_MAX;
int total_runs = 0;
long long total_ticks = 0;
FILE *fraw;
double d_arg = 0;

#ifdef _MSC_VER
LARGE_INTEGER time_freq;
LARGE_INTEGER time_start;
LARGE_INTEGER time_end;
#endif

// tallies of run count and tick count per byte per position
struct tally {
    long long num; // times tallied
    double ticks; // total ticks
};

// Returns largest cache size (intel only, using cpuid)
// source: https://stackoverflow.com/questions/12594208/c-program-to-determine-levels-size-of-cache
size_t cache_size(void) {
    uint32_t eax, ebx, ecx, edx;
    size_t largest = 0;
    for (int i = 0; i < 32; i++) {
        eax = 4; // get cache info
        ecx = i; // cache id

#ifdef _MSC_VER
    int tmp[4];
    __cpuidex(tmp, eax, ecx);
    eax = tmp[0], ebx = tmp[1], ecx = tmp[2], edx = tmp[3];
#else
    __asm__(
        "cpuid"
        : "+a" (eax)
        , "=b" (ebx)
        , "+c" (ecx)
        , "=d" (edx)
    );
#endif

        if ((eax & 0x1F) == 0) break; // end of valid cache identifiers

        // taken from http://download.intel.com/products/processor/manual/325462.pdf 3-166 Vol. 2A
        // ebx contains 3 integers of 10, 10 and 12 bits respectively
        unsigned int cache_sets = ecx + 1;
        unsigned int cache_coherency_line_size = (ebx & 0xFFF) + 1;
        unsigned int cache_physical_line_partitions = ((ebx >>= 12) & 0x3FF) + 1;
        unsigned int cache_ways_of_associativity = ((ebx >>= 10) & 0x3FF) + 1;

        // Total cache size is the product
        size_t cache_total_size = cache_ways_of_associativity * cache_physical_line_partitions * cache_coherency_line_size * cache_sets;
        largest = cache_total_size > largest ? cache_total_size : largest;
    }
    return largest;
}

// seed the rand() PRNG
void rand_seed(void) {
    srand(__rdtsc());
}

// generate <num> pseudorandom bytes and place them in <dest>
void rand_bytes(byte *dest, int num) {
#if OPENSSL_RAND == 1
    RAND_bytes(dest, num);
#else
    for (byte i = 0; i < num; ++i)
        dest[i] = rand();
#endif
}

// dump cleartext block and ticks taken to encrypt it
void raw_dump(byte *data, int ticks) {
#if RAW_OUTPUT_ASCII == 1
    fprintf(fraw, "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %d\n",
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            data[9], data[10], data[11], data[12], data[13], data[14], data[15], ticks);
#else
    fwrite(data, 16, 1, fraw);
    fwrite(&ticks, sizeof(int), 1, fraw);
#endif
}

// print the provided AES-128 <key> named <name> to <fout>
void print_key(const char *name, const byte *key, FILE *fout) {
    fprintf(fout, "%s: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", name,
            key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], key[8],
            key[9], key[10], key[11], key[12], key[13], key[14], key[15]);
}

// encrypts a <data> block, places the encrypted block in <encdata> and returns ticks taken
int run(byte *data) {
    long long start;

#if PURGE_CACHE
#ifdef _MSC_VER
    SecureZeroMemory(CACHE, CACHE_SIZE);
#else
    explicit_bzero(CACHE, CACHE_SIZE);
#endif
#endif

    start = __rdtsc();
#if PREEMPTIVE_KEYEXPAND == 1
#ifdef USE_OPENSSL
    AES_encrypt(data, encdata, &expanded_key);
#else
    aes(data, encdata);
#endif
#else
#ifdef USE_OPENSSL
    AES_set_encrypt_key(current_key, 128, &expanded_key);
    AES_encrypt(data, encdata, &expanded_key);
#else
    aes_expand(current_key);
    aes(data, encdata);
#endif
#endif
    return __rdtsc() - start;
}

// TODO
// encrypts a <data> block and tallies measurements in <tly>
// tallies are indexed by cleartext as tly[position][cleartext byte]
// updates total_runs and total_ticks with respective values
void generate(byte *data, struct tally tly[][256]) {
    struct tally *ptr;
    int ticks;

    // randomize data
    rand_bytes(data, 16);

    // encrypt
    do {
        ticks = run(data);
    } while (ticks > tally_threshold);

#if VERBOSE > 2
    raw_dump(data, ticks);
#endif

    /* YOUR CODE HERE
     * Perform tallies for used cleartext
     */
}

// sets current encryption key and expands it (if PREEMPTIVE_KEYEXPAND is used)
void expand_key(byte *key) {
    current_key = key;
    #if PREEMPTIVE_KEYEXPAND == 1
    #ifdef USE_OPENSSL
    AES_set_encrypt_key(key, 128, &expanded_key);
    #else
    aes_expand(key);
    #endif
    #endif
}

// performs a set number of encryptions to set cutoff threshold
// returns the rate of encryptions per second (and prints it to <frate_name>)
void calc_encryption_stats(byte *key, byte *data, int runs) {
    struct timespec start, end;
    double rate;

    // If threshold is set, do not calculate it
    if (d_arg > 0) {
        tally_threshold = d_arg;
        return;
    }

    rand_seed();
    rand_bytes(key, 16); // generate random key
    expand_key(key);
    print_key("Cutoff", key, stdout);
#ifdef _MSC_VER
    QueryPerformanceCounter(&time_start);
#else
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif
    for (total_runs = 0; total_runs < runs; ++total_runs) {
        // randomize data
        rand_bytes(data, 16);

        total_ticks += run(data);
    }
#ifdef _MSC_VER
    QueryPerformanceCounter(&time_end);
    rate = W_TIME_DIFF;
#else
    clock_gettime(CLOCK_MONOTONIC, &end);
    rate = (double)TIME_DIFF(start, end) / 1000000000;
#endif

    rate = (double) runs / rate;
    tally_threshold = total_ticks / total_runs * THRESH_MULT;

    FILE *f = fopen(frate_name, "w");
    fprintf(f, "%lf\n%d\n", rate, tally_threshold);
    fclose(f);

    printf("Cutoff: %lld Mticks total, avg: %lld, thresh: %d, %d enc./s\n", total_ticks / 1000000, total_ticks / runs, tally_threshold, (int) rate);
}

// sorts zipped bytes with double vals in reverse
int cmp_zip(const void *vp1, const void *vp2, void *vvals) {
    byte *p1 = (byte *) vp1, *p2 = (byte *) vp2;
    double *val = (double *) vvals;
    if (val[*p2] > val[*p1]) return 1;
    if (val[*p1] > val[*p2]) return -1;
    return 0;
}

// Comparators for qsort_s
int cmp_zip_win(void *vvals, const void *vp1, const void *vp2) {
    return cmp_zip(vp1, vp2, vvals);
}

// TODO
// calculates normalized means from <tly> structs and places them in <means>
void calc_means(struct tally tly[][256], double means[][256]) {
    /* YOUR CODE HERE
     * Populate means[16][256] with the normalized mean of ticks per position per cleartext byte (means[position][cleartext byte])
     * Each tally struct contains tallies for a byte at a given position (tly[position][cleartext byte])
     * Hint: normalize means by the global mean
     */
}

// prints run count and normalized mean for all key byte values and positions
void print_means(struct tally tly[][256], double means[][256], const byte *key, const char *fname) {
    struct tally *ptly;
    double *pmeans;
    byte pos[256];
    FILE *f  = fopen(fname, "w");
    print_key("Key", key, f);
    fprintf(f, "Average: %lf", (double) total_ticks / total_runs);

    for (int i = 0; i < 16; ++i) {
        // Sort by average ticks
        for (int b = 0; b < 256; ++b) {
            pos[b] = b; // set up initial position sequence
        }

#ifdef _MSC_VER
        qsort_s(pos, 256, sizeof(byte), cmp_zip_win, means[i]);
#else
        qsort_r(pos, 256, sizeof(byte), cmp_zip, means[i]);
#endif
        for (int b = 0; b < 256; ++b) {
            ptly = &tly[i][pos[b]];
            pmeans = &means[i][pos[b]];
            fprintf(f, "%2d %02x %lld %lf\n", i, pos[b], ptly->num, *pmeans);
        }
    }
    fclose(f);
}

// Correlates two datasets of size 256 using the pearsons's correlation coefficient
double pearson_correlation_coefficient(double *data1, double *data2) {
    double sum_x_sq, sum_y_sq, avg_x, avg_y, var_x, var_y, sum_x_y;

    // first calculate prerequisite statistics
    sum_x_sq = sum_y_sq = avg_x = avg_y = sum_x_y = 0;
    for (int i = 0; i < 256; ++i) {
        avg_x += data1[i];
        avg_y += data2[i];
        sum_x_sq += data1[i] * data1[i];
        sum_y_sq += data2[i] * data2[i];
        sum_x_y += data1[i] * data2[i];
    }
    avg_x /= 256, avg_y /= 256;
    var_x = (sum_x_sq - 256 * avg_x * avg_x) / 255;
    var_y = (sum_y_sq - 256 * avg_y * avg_y) / 255;

    return (sum_x_y - 256 * avg_x * avg_y) / 255 / sqrt(var_x * var_y);
}

// TODO
// corr[position][candidate byte] is populated with pearson's correlation coefficients per byte per position
// the means in <means1> (known-key measurement with key <key>) and <means2> (unknown-key measurement) are taken per cleartext byte
// correlations are taken per key byte XOR cleartext byte, ie. the input for the first-round AES T-BOX lookup
void correlate(double means1[][256], double means2[][256], const byte *key, double corr[][256]) {

    /* YOUR CODE HERE
     * Fill <corr> with pearson's correlation coefficients for all possible target key bytes on all positions (16*256)
     * The provided means are indexed by cleartext bytes.
     * The first round of AES uses key XOR input as the state. To properly correlate the timings, you need to mix the key into the indices.
     * Hint: use pearson_correlation_coefficient() above
     */
}

// dump sorted (and possibly annotated) correlations to <filename>
void dump_corr(double corr[][256], const char *filename) {
    FILE *f = fopen(filename, "w");
    byte pos[256];
    double val;

    for (int i = 0; i < 16; ++i) {
        // Sort by correlation
        for (int b = 0; b < 256; ++b) {
            pos[b] = b; // set up initial position sequence
        }
#ifdef _MSC_VER
        qsort_s(pos, 256, sizeof(byte), cmp_zip_win, corr[i]);
#else
        qsort_r(pos, 256, sizeof(byte), cmp_zip, corr[i]);
#endif
        for (int b = 0; b < 256; ++b) {
            val = corr[i][pos[b]];
            fprintf(f, "%2d %02x %lf", i, pos[b], val);
            // DEBUGGING INFO: mark matching bytes
            fprintf(f, (DEBUG && pos[b] == target_key[i]) ? " ***\n" : "\n");
#if VERBOSE > 1
            if (b < 16 && pos[b] == target_key[i]) {
                printf("%x (%.2lf):", i, val);
                for (int j = 0; j < 16; ++j)
                    if (pos[j] == target_key[i])
                        printf(" \x1b[38;5;1m%02x\x1b[0m", pos[j]);
                    else
                        printf(" %02x", pos[j]);
                printf("\n");
            }
#endif
        }
    }

    fclose(f);
}

// prioritize main process as much as possible
void set_process_attributes(void) {
#ifdef _MSC_VER
    // Set process priority to realtime on Core 0
    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    SetProcessAffinityMask(GetCurrentProcess(), 1);
#else
    // Set process priority to RT/FIFO 99 on Core 0
    struct sched_param p;
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(0, &set);
    p.sched_priority = 99;
    sched_setaffinity(getpid(), sizeof(set), &set);
    sched_setscheduler(getpid(), SCHED_FIFO, &p);
#endif
}

// gather time side-channel data for a given <test_key>
void study_key(
        struct tally tly[][256],
        double means[][256],
        byte *data,
        byte *test_key,
        byte gen_key,
        int runs,
        int run_id)
{
    char k_name[32];
    sprintf(k_name, "%d. key", run_id);

    // clear tally
    memset(tly, 0, 16 * 256 * sizeof(struct tally));

    // seed random generator
    rand_seed();

    // generate new key
    if (gen_key)
        rand_bytes(test_key, 16);
    expand_key(test_key);
    print_key(k_name, test_key, stdout);

    // Run
    total_ticks = total_runs = 0; // zero out counters

    for (int i = 0; i < runs; ++i) {
        generate(data, tly);
    }

    calc_means(tly, means);
#if VERBOSE > 1
    sprintf(k_name, "tally%d.txt", run_id);
    print_means(tly, means, test_key, k_name);
#endif
    printf("%d. key: %lld Mticks total, %lld ticks on average\n", run_id, total_ticks / 1000000, total_ticks / runs);
}

// test if the provided <key> encrypts the <data> cleartext to <target_enctext>
int brute_force_attempt(byte *key, byte *data, const byte *target_enctext) {
    expand_key(key);
    run(data);
    for (int i = 0; i < 16; ++i) {
        if (target_enctext[i] != encdata[i])
            return 1;
    }

    print_key("Cracked key", key, stdout);
    return 0;
}

// if <bf_fname> file exists, read it and begin brute-forcing
// returns: -1 = not brute forcing, 0 = success, 1 = failure
int brute_force(void) {
    byte bytes[16][256], order[16], key[16], target_enctext[16], cleartext[16] = { 0 };
    int lens[16] = { 0 }, indices[16] = { 0 };
    double d_lens[16]; // my comparator needs doubles and I'm lazy to write another one for ints

    FILE *f = fopen(bf_name, "rb");
    if (!f) return -1;

    // scrambled zero of the target key
    expand_key(target_key);
    run(cleartext);
    memcpy(target_enctext, encdata, 16);

    for (int i = 0; i < 16; ++i) {
        if (fread(lens + i, 1, 1, f) != 1) return 1;
        if (lens[i] == 0) lens[i] = 256;
        if (fread(bytes[i], 1, lens[i], f) != (size_t) lens[i]) return 1;
        order[i] = i;
        d_lens[i] = lens[i];
    }
    fclose(f);

    // first reorder the pools to keep the smallest ones high
    // this way the ones we're so sure of won't change so often, increasing our hit chance
#ifdef _MSC_VER
    qsort_s(order, 16, sizeof(byte), cmp_zip_win, d_lens);
#else
    qsort_r(order, 16, sizeof(byte), cmp_zip, d_lens);
#endif

    // key space iteration starts from the lowest position upwards
    byte *ptr = order, *end = order + 16;
    while (ptr < end) {
        ptr = order; // start from the beginning
        // try this index configuration
        for (int i = 0; i < 16; ++i) key[i] = bytes[i][indices[i]];
        if (!brute_force_attempt(key, cleartext, target_enctext))
            return 0;

        // carry upwards
        while (++indices[*ptr] >= lens[*ptr]) {
            indices[*ptr] = 0;
            if (++ptr >= end) break;
        }
    }

    return 1;
}

int main(int argc, char* argv[]) {
    int runs; // number of runs for both cutoff calculation and individual runs
    byte test_key[16], data[16]; // working keys and clear-text block
    struct tally tly[16][256]; // number of runs and ticks for each position and byte
    double means_test[16][256], means_target[16][256]; // normalized tick means for each position and byte
    double corr[16][256], corr_total[16][256]; // correlations

#if PRIORITIZE_PROCESS == 1
    // Request high priority and lock on a single core as soon as possible
    set_process_attributes();
#endif
#ifdef _MSC_VER
    // Windows specific: set timer frequency
    QueryPerformanceFrequency(&time_freq);
#endif

#ifndef USE_OPENSSL
    // Initialize your AES implementation
    aes_init();
#endif

    // read argument if provided
    if (argc > 1)
        d_arg = strtod(argv[1], NULL);

#if RANDOMIZE_KEY == 0
    // Read key from file
    FILE *fkey = fopen(fkey_name, "r");
    if (!fkey || fread(target_key, 1, 16, fkey) != 16) {
        printf("Unable to read 16 bytes from %s\n", fkey_name);
        return 1;
    }
    fclose(fkey);
#endif

    // Check if brute-force candidates exist
    int rc = brute_force();
    if (rc > -1) return rc;

    // Set runs to the according power of 2
    runs = 1 << DEFAULT_RUNS; // 2 ^ runs

#if PURGE_CACHE == 1
    CACHE_SIZE = cache_size();
    CACHE = malloc(CACHE_SIZE);
#endif
#if VERBOSE > 0
    char corr_filename[32];
#endif
#if VERBOSE > 2
    fraw = fopen(fraw_name, "w");
#endif
#if THRESH_ON == 1
    calc_encryption_stats(test_key, data, runs);
#endif

    // target key analysis
#if RANDOMIZE_KEY == 1
    printf("Generating random secret key");
    study_key(tly, means_target, data, target_key, 1, runs, 0);
#else
    study_key(tly, means_target, data, target_key, 0, runs, 0);
#endif

    // zero out correlation totals
    memset(corr_total, 0, 16 * 256 * sizeof(double));

    // perform test runs with random keys and correlate them with the target key
    for (int i = 1; i <= KEYS_CAP; ++i) {
        study_key(tly, means_test, data, test_key, 1, runs, i);
        correlate(means_test, means_target, test_key, corr);

        // add correlations to total
        for (int j = 0; j < 16; ++j) {
            for (int k = 0; k < 256; ++k) {
                corr_total[j][k] += corr[j][k];
            }
        }
#if VERBOSE > 0
            // analyze partial result
            sprintf(corr_filename, "corr%d.txt", i);
            dump_corr(corr, corr_filename);
#endif
    }

    dump_corr(corr_total, "corr.txt");

#if PURGE_CACHE == 1
    free(CACHE);
#endif
#if VERBOSE > 2
    fclose(fraw);
#endif

    return 0;
}
