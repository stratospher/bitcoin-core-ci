/***********************************************************************
 * Copyright (c) 2022 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ELLSWIFT_BENCH_H
#define SECP256K1_MODULE_ELLSWIFT_BENCH_H

#include "../include/secp256k1_ellswift.h"

typedef struct {
    secp256k1_context *ctx;
    secp256k1_pubkey point;
    unsigned char rnd64[64];
} bench_ellswift_data;

static void bench_ellswift_setup(void* arg) {
    bench_ellswift_data *data = (bench_ellswift_data*)arg;
    static const unsigned char point[] = {
        0x03,
        0x54, 0x94, 0xc1, 0x5d, 0x32, 0x09, 0x97, 0x06,
        0xc2, 0x39, 0x5f, 0x94, 0x34, 0x87, 0x45, 0xfd,
        0x75, 0x7c, 0xe3, 0x0e, 0x4e, 0x8c, 0x90, 0xfb,
        0xa2, 0xba, 0xd1, 0x84, 0xf8, 0x83, 0xc6, 0x9f
    };
    memcpy(data->rnd64, point, 32);
    memcpy(data->rnd64 + 32, point + 1, 32);
    CHECK(secp256k1_ec_pubkey_parse(data->ctx, &data->point, point, sizeof(point)) == 1);
}

static void bench_ellswift_encode(void* arg, int iters) {
    int i;
    bench_ellswift_data *data = (bench_ellswift_data*)arg;

    for (i = 0; i < iters; i++) {
        data->rnd64[19] ^= 247;
        data->rnd64[47] ^= 113;
        CHECK(secp256k1_ellswift_encode(data->ctx, data->rnd64, &data->point, data->rnd64 + 16) == 1);
    }
}

static void bench_ellswift_create(void* arg, int iters) {
    int i, j;
    bench_ellswift_data *data = (bench_ellswift_data*)arg;

    for (i = 0; i < iters; i++) {
        unsigned char out64[64];
        CHECK(secp256k1_ellswift_create(data->ctx, out64, data->rnd64, data->rnd64 + 32) == 1);
        for (j = 0; j < 64; j++) data->rnd64[j] ^= out64[j];
    }
}

static void bench_ellswift_decode(void* arg, int iters) {
    int i;
    secp256k1_pubkey out;
    bench_ellswift_data *data = (bench_ellswift_data*)arg;

    for (i = 0; i < iters; i++) {
        data->rnd64[13] ^= 247;
        data->rnd64[49] ^= 113;
        CHECK(secp256k1_ellswift_decode(data->ctx, &out, data->rnd64) == 1);
        memcpy(data->rnd64 + 16, &out.data, 32);
    }
}

static void bench_ellswift_xdh(void* arg, int iters) {
    int i;
    bench_ellswift_data *data = (bench_ellswift_data*)arg;

    for (i = 0; i < iters; i++) {
        data->rnd64[13] ^= 247;
        data->rnd64[49] ^= 113;
        CHECK(secp256k1_ellswift_xdh(data->ctx, data->rnd64 + 16, data->rnd64, data->rnd64, data->rnd64 + 13, NULL, NULL) == 1);
    }
}

void run_ellswift_bench(int iters, int argc, char** argv) {
    bench_ellswift_data data;
    int d = argc == 1;

    /* create a context with signing capabilities */
    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    memset(data.rnd64, 11, sizeof(data.rnd64));

    if (d || have_flag(argc, argv, "ellswift") || have_flag(argc, argv, "encode") || have_flag(argc, argv, "ellswift_encode")) run_benchmark("ellswift_encode", bench_ellswift_encode, bench_ellswift_setup, NULL, &data, 10, iters);
    if (d || have_flag(argc, argv, "ellswift") || have_flag(argc, argv, "decode") || have_flag(argc, argv, "ellswift_decode")) run_benchmark("ellswift_decode", bench_ellswift_decode, bench_ellswift_setup, NULL, &data, 10, iters);
    if (d || have_flag(argc, argv, "ellswift") || have_flag(argc, argv, "create") || have_flag(argc, argv, "ellswift_create")) run_benchmark("ellswift_create", bench_ellswift_create, bench_ellswift_setup, NULL, &data, 10, iters);
    if (d || have_flag(argc, argv, "ellswift") || have_flag(argc, argv, "xdh") || have_flag(argc, argv, "ellswift_xdh")) run_benchmark("ellswift_xdh", bench_ellswift_xdh, bench_ellswift_setup, NULL, &data, 10, iters);

    secp256k1_context_destroy(data.ctx);
}

#endif /* SECP256K1_MODULE_ellswift_BENCH_H */
