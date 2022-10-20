/***********************************************************************
 * Copyright (c) 2022 Pieter Wuile                                     *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ELLSWIFT_TESTS_H
#define SECP256K1_MODULE_ELLSWIFT_TESTS_H

#include "../../../include/secp256k1_ellswift.h"

struct ellswift_test_vec {
    int enc_bitmap;
    secp256k1_fe u;
    secp256k1_fe x;
    secp256k1_fe encs[8];
};

/* Set of (point, encodings) test vectors, selected to maximize branch coverage.
 * Created using an independent implementation, and tested against paper author's code. */
static const struct ellswift_test_vec ellswift_tests[] = {
    {0x33, SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), {SECP256K1_FE_CONST(0x2c8864a8, 0xc34e87d7, 0x53ee7300, 0x8bbed54a, 0x47b37907, 0x56d0b747, 0x10341b37, 0xf598a5fe), SECP256K1_FE_CONST(0x15908d62, 0x2377bedc, 0x0fecf55f, 0xcc6425c9, 0xde992fcb, 0x01af2628, 0xac40f220, 0x88de01f0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0xd3779b57, 0x3cb17828, 0xac118cff, 0x74412ab5, 0xb84c86f8, 0xa92f48b8, 0xefcbe4c7, 0x0a675631), SECP256K1_FE_CONST(0xea6f729d, 0xdc884123, 0xf0130aa0, 0x339bda36, 0x2166d034, 0xfe50d9d7, 0x53bf0dde, 0x7721fa3f), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0x44, SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), SECP256K1_FE_CONST(0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaa9, 0xfffffd6b), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0x4218f20a, 0xe6c646b3, 0x63db6860, 0x5822fb14, 0x264ca8d2, 0x587fdd6f, 0xbc750d58, 0x7e76a7ee), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0xbde70df5, 0x1939b94c, 0x9c24979f, 0xa7dd04eb, 0xd9b3572d, 0xa7802290, 0x438af2a6, 0x81895441), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0x00, SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), SECP256K1_FE_CONST(0x31d8011e, 0x503be7cd, 0x04ed2465, 0x4f09771e, 0x721346f2, 0x2c5b5fee, 0x14f5c5c1, 0x56167823), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0x00, SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), SECP256K1_FE_CONST(0xb8438fb4, 0x2a2cead9, 0xace238da, 0x755840bf, 0x6ca51d4c, 0x6eb4074c, 0x43b215de, 0x5711e680), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0xcc, SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), SECP256K1_FE_CONST(0xf5df3913, 0x4f41d9f0, 0xa9c7c4ad, 0xa1c76e02, 0xc92d9e3f, 0xd5de26f4, 0x7e39e55e, 0xef6d1717), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0x1db9675d, 0x54da4f19, 0x8bc3ba39, 0xc91d945a, 0x30eb2963, 0xc63eb119, 0x606d6a45, 0xc857dbe0), SECP256K1_FE_CONST(0x3b9efb64, 0xe9d56bf7, 0xee4bc029, 0x288e000e, 0x875be218, 0xd92fca16, 0xda6b82fe, 0xb7035c86), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0xe24698a2, 0xab25b0e6, 0x743c45c6, 0x36e26ba5, 0xcf14d69c, 0x39c14ee6, 0x9f9295b9, 0x37a8204f), SECP256K1_FE_CONST(0xc461049b, 0x162a9408, 0x11b43fd6, 0xd771fff1, 0x78a41de7, 0x26d035e9, 0x25947d00, 0x48fc9fa9)}},
    {0x00, SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), SECP256K1_FE_CONST(0x7975920f, 0x7dd28f06, 0x0b90de63, 0xaa069e8c, 0x34858639, 0xf4a77e0d, 0x9774649e, 0xb9087bac), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0x33, SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), SECP256K1_FE_CONST(0x3125472c, 0x4bca81e7, 0xfa8493d7, 0x253f29c8, 0x8a51d3ec, 0x7afefaae, 0x19f87a91, 0xc6c35775), {SECP256K1_FE_CONST(0x3a14b35f, 0x5b086a06, 0xf6b746cb, 0x79730ca2, 0x202855e7, 0xe1bbfdca, 0x1aa809bd, 0x810ff058), SECP256K1_FE_CONST(0xe116acef, 0x46c0d624, 0x6dc90c90, 0x714ad693, 0x47b24bdc, 0x2b07c677, 0xa7a24d13, 0xcba4d6ec), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0xc5eb4ca0, 0xa4f795f9, 0x0948b934, 0x868cf35d, 0xdfd7aa18, 0x1e440235, 0xe557f641, 0x7ef00bd7), SECP256K1_FE_CONST(0x1ee95310, 0xb93f29db, 0x9236f36f, 0x8eb5296c, 0xb84db423, 0xd4f83988, 0x585db2eb, 0x345b2543), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0x33, SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), SECP256K1_FE_CONST(0x7f39a9ef, 0x29f9d846, 0x5a1a18e1, 0x3ed5d07b, 0x613f8094, 0x96700779, 0xd81d8e89, 0x59b2e8c5), {SECP256K1_FE_CONST(0x1788e280, 0x7a2a0adc, 0xeb6cfa2e, 0xa176478b, 0xaee9b178, 0xbd2c3819, 0xe56e54c2, 0x6e4fccbd), SECP256K1_FE_CONST(0xc5983497, 0x8137ee51, 0xb41566c7, 0xb56c7df1, 0xe9ccd528, 0xfe0db5da, 0x33c95ff8, 0xf1b96212), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0xe8771d7f, 0x85d5f523, 0x149305d1, 0x5e89b874, 0x51164e87, 0x42d3c7e6, 0x1a91ab3c, 0x91b02f72), SECP256K1_FE_CONST(0x3a67cb68, 0x7ec811ae, 0x4bea9938, 0x4a93820e, 0x16332ad7, 0x01f24a25, 0xcc36a006, 0x0e469a1d), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0x00, SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), SECP256K1_FE_CONST(0xf30a866b, 0x849cd237, 0x534f9089, 0xaed6bfcf, 0x8dd9952b, 0xd77346f6, 0xd426158b, 0xc82be41a), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0xff, SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), SECP256K1_FE_CONST(0xdd7328f6, 0x725a645a, 0x4224d125, 0x455291fb, 0x3eeabb13, 0x6151926f, 0x5ca6d4c2, 0x849e3ef6), {SECP256K1_FE_CONST(0x362565da, 0x03102cb1, 0x084ab68f, 0xb28babcc, 0x3f9165e2, 0x4070e29a, 0x238ca4d1, 0x88b0c8ad), SECP256K1_FE_CONST(0xa3e8fec6, 0x1c9c7267, 0xda96f709, 0x958f8065, 0xaf5a59c2, 0xe2375058, 0x4b7ccc68, 0x6f31cf07), SECP256K1_FE_CONST(0x38c4364d, 0x829d26d1, 0xfd5d0080, 0xf399db60, 0xe3ff1836, 0xaff5d615, 0x42fc04b5, 0xdc690ffd), SECP256K1_FE_CONST(0x6d6333ac, 0x7a4cbac0, 0x458657c3, 0x898bf188, 0x30d4ba43, 0xf7ce7115, 0x54f3d846, 0x6023d718), SECP256K1_FE_CONST(0xc9da9a25, 0xfcefd34e, 0xf7b54970, 0x4d745433, 0xc06e9a1d, 0xbf8f1d65, 0xdc735b2d, 0x774f3382), SECP256K1_FE_CONST(0x5c170139, 0xe3638d98, 0x256908f6, 0x6a707f9a, 0x50a5a63d, 0x1dc8afa7, 0xb4833396, 0x90ce2d28), SECP256K1_FE_CONST(0xc73bc9b2, 0x7d62d92e, 0x02a2ff7f, 0x0c66249f, 0x1c00e7c9, 0x500a29ea, 0xbd03fb49, 0x2396ec32), SECP256K1_FE_CONST(0x929ccc53, 0x85b3453f, 0xba79a83c, 0x76740e77, 0xcf2b45bc, 0x08318eea, 0xab0c27b8, 0x9fdc2517)}},
    {0xcc, SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), SECP256K1_FE_CONST(0xf0f46c7e, 0x8c23f563, 0x18550c00, 0x2ef33695, 0x01220ba3, 0xe25cb308, 0x4013711f, 0xb679743f), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0x8e574be1, 0xbba447e9, 0x85f3ee1f, 0x4940c0ee, 0x27087f6d, 0xfb739fdd, 0x05aa1bb3, 0xfbc5b224), SECP256K1_FE_CONST(0xd1c89542, 0x677cfeb2, 0xf20712a2, 0x35033c21, 0x2b7a7446, 0xbc99894f, 0xd2d0651f, 0x20b75905), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0x71a8b41e, 0x445bb816, 0x7a0c11e0, 0xb6bf3f11, 0xd8f78092, 0x048c6022, 0xfa55e44b, 0x043a4a0b), SECP256K1_FE_CONST(0x2e376abd, 0x9883014d, 0x0df8ed5d, 0xcafcc3de, 0xd4858bb9, 0x436676b0, 0x2d2f9adf, 0xdf48a32a)}},
    {0x33, SECP256K1_FE_CONST(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xfffffc2e), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), {SECP256K1_FE_CONST(0x2bd4bfb6, 0x851f02c7, 0xb9e42ee0, 0x1243906f, 0x0272ec4e, 0xad1781cc, 0x345affbc, 0x83aa54ef), SECP256K1_FE_CONST(0x3750ab59, 0xd50a6745, 0x5be4edb0, 0x71f0e82f, 0x370010ec, 0xd7a84a5b, 0x66549448, 0x3a07a6f6), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0xd42b4049, 0x7ae0fd38, 0x461bd11f, 0xedbc6f90, 0xfd8d13b1, 0x52e87e33, 0xcba50042, 0x7c55a740), SECP256K1_FE_CONST(0xc8af54a6, 0x2af598ba, 0xa41b124f, 0x8e0f17d0, 0xc8ffef13, 0x2857b5a4, 0x99ab6bb6, 0xc5f85539), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0x00, SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 2), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 2), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0xcc, SECP256K1_FE_CONST(0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x7ffffe18), SECP256K1_FE_CONST(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xfffffc13), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0xefbd23d5, 0x2ebf879f, 0x228dbeb0, 0x5c85881a, 0xdb886b53, 0x23bda366, 0x4520a05e, 0x6c549854), SECP256K1_FE_CONST(0x1326b8de, 0x9cad16c3, 0xc859d692, 0xfbc6c22a, 0x78698964, 0x86e0b713, 0x174982af, 0x7d28eb8d), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0x1042dc2a, 0xd1407860, 0xdd72414f, 0xa37a77e5, 0x247794ac, 0xdc425c99, 0xbadf5fa0, 0x93ab63db), SECP256K1_FE_CONST(0xecd94721, 0x6352e93c, 0x37a6296d, 0x04393dd5, 0x8796769b, 0x791f48ec, 0xe8b67d4f, 0x82d710a2)}},
    {0xff, SECP256K1_FE_CONST(0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x7ffffe17), SECP256K1_FE_CONST(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xfffffc13), {SECP256K1_FE_CONST(0x6342f23b, 0x31f75ef3, 0x861b36fc, 0x33383cfb, 0x43d08212, 0xe42ad82b, 0x5b397b00, 0x005ebee7), SECP256K1_FE_CONST(0xf3d7c0d4, 0x14a2d008, 0x4251039d, 0x4ad2978e, 0x0c5a2094, 0x5f21755b, 0xf3873e00, 0x2c359f65), SECP256K1_FE_CONST(0xa14a6f4e, 0x4006cb83, 0x7201f076, 0x58ca4e2e, 0x369402df, 0xa5b9a6a2, 0x6522fd67, 0x3916dfa4), SECP256K1_FE_CONST(0x8beba960, 0x40d7d2bd, 0xb9af082d, 0xfc7ff55f, 0x29e55f15, 0xa6826848, 0x6dd89b37, 0x3cb586b1), SECP256K1_FE_CONST(0x9cbd0dc4, 0xce08a10c, 0x79e4c903, 0xccc7c304, 0xbc2f7ded, 0x1bd527d4, 0xa4c684fe, 0xffa13d48), SECP256K1_FE_CONST(0x0c283f2b, 0xeb5d2ff7, 0xbdaefc62, 0xb52d6871, 0xf3a5df6b, 0xa0de8aa4, 0x0c78c1fe, 0xd3ca5cca), SECP256K1_FE_CONST(0x5eb590b1, 0xbff9347c, 0x8dfe0f89, 0xa735b1d1, 0xc96bfd20, 0x5a46595d, 0x9add0297, 0xc6e91c8b), SECP256K1_FE_CONST(0x7414569f, 0xbf282d42, 0x4650f7d2, 0x03800aa0, 0xd61aa0ea, 0x597d97b7, 0x922764c7, 0xc34a757e)}},
    {0x00, SECP256K1_FE_CONST(0x6e340b9c, 0xffb37a98, 0x9ca544e6, 0xbb780a2c, 0x78901d3f, 0xb3373876, 0x8511a306, 0x17afa01d), SECP256K1_FE_CONST(0x91cbf463, 0x004c8567, 0x635abb19, 0x4487f5d3, 0x876fe2c0, 0x4cc8c789, 0x7aee5cf8, 0xe8505c12), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0x77, SECP256K1_FE_CONST(0x6e340b9c, 0xffb37a98, 0x9ca544e6, 0xbb780a2c, 0x78901d3f, 0xb3373876, 0x8511a306, 0x17afa01d), SECP256K1_FE_CONST(0x161462dd, 0x57fffa52, 0x1137bcd7, 0x9ed6981a, 0x726e402a, 0xc56b081c, 0x2bbe912e, 0x3132360d), {SECP256K1_FE_CONST(0x51fe8154, 0x3cba720f, 0x207dab99, 0x1262b65e, 0xa1b89324, 0x25fd389b, 0xcdb6a339, 0x7b045976), SECP256K1_FE_CONST(0x866f19a8, 0xdda199c9, 0x22157b84, 0x46ded073, 0xa4d67b2e, 0x893675dd, 0xd99aaaba, 0xe7bf1a25), SECP256K1_FE_CONST(0xae574801, 0x101b2890, 0xd3c2d4ba, 0xc6cb4559, 0x0d9ebe59, 0x6e75638a, 0xa8d65f54, 0xc56f6004), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0xae017eab, 0xc3458df0, 0xdf825466, 0xed9d49a1, 0x5e476cdb, 0xda02c764, 0x32495cc5, 0x84fba2b9), SECP256K1_FE_CONST(0x7990e657, 0x225e6636, 0xddea847b, 0xb9212f8c, 0x5b2984d1, 0x76c98a22, 0x26655544, 0x1840e20a), SECP256K1_FE_CONST(0x51a8b7fe, 0xefe4d76f, 0x2c3d2b45, 0x3934baa6, 0xf26141a6, 0x918a9c75, 0x5729a0aa, 0x3a909c2b), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0x33, SECP256K1_FE_CONST(0x6e340b9c, 0xffb37a98, 0x9ca544e6, 0xbb780a2c, 0x78901d3f, 0xb3373876, 0x8511a306, 0x17afa01d), SECP256K1_FE_CONST(0x2c1c4d0d, 0x41ecda63, 0xb4131edb, 0x65fef49e, 0xf3f6b770, 0x00de1432, 0xc21355a4, 0x2ad19091), {SECP256K1_FE_CONST(0xa1b6e32d, 0x9a3b31b5, 0xecad712f, 0x72bfe460, 0x587dcea9, 0x5c6c65c1, 0xaa1dad5a, 0xa4cf57c0), SECP256K1_FE_CONST(0xf5696de5, 0x3dba0943, 0xafe12a72, 0x0049b0a8, 0x6f6cde0e, 0xd4a5eb64, 0xb7f52a8b, 0x464cbedb), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0x5e491cd2, 0x65c4ce4a, 0x13528ed0, 0x8d401b9f, 0xa7823156, 0xa3939a3e, 0x55e252a4, 0x5b30a46f), SECP256K1_FE_CONST(0x0a96921a, 0xc245f6bc, 0x501ed58d, 0xffb64f57, 0x909321f1, 0x2b5a149b, 0x480ad573, 0xb9b33d54), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0xcc, SECP256K1_FE_CONST(0x4bf5122f, 0x344554c5, 0x3bde2ebb, 0x8cd2b7e3, 0xd1600ad6, 0x31c385a5, 0xd7cce23c, 0x7785459a), SECP256K1_FE_CONST(0x71a59aaa, 0x83bff3a0, 0x53323c20, 0xa43aa0ff, 0x3b17f582, 0xd245ba85, 0xb2ad61cf, 0x91df00bf), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0xaa89b76b, 0x710916f7, 0x7e57e7bf, 0xd726ad9d, 0x27e90d86, 0x18903b0a, 0x1852b680, 0x478b687c), SECP256K1_FE_CONST(0x6fa74a38, 0x06a04766, 0xdd1d2ed9, 0x81466c12, 0x8ec84ade, 0x00ff9883, 0xb4354956, 0x0834fde1), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0x55764894, 0x8ef6e908, 0x81a81840, 0x28d95262, 0xd816f279, 0xe76fc4f5, 0xe7ad497e, 0xb87493b3), SECP256K1_FE_CONST(0x9058b5c7, 0xf95fb899, 0x22e2d126, 0x7eb993ed, 0x7137b521, 0xff00677c, 0x4bcab6a8, 0xf7cafe4e)}},
    {0xcc, SECP256K1_FE_CONST(0xe52d9c50, 0x8c502347, 0x344d8c07, 0xad91cbd6, 0x068afc75, 0xff6292f0, 0x62a09ca3, 0x81c89e71), SECP256K1_FE_CONST(0x1ad263af, 0x73afdcb8, 0xcbb273f8, 0x526e3429, 0xf975038a, 0x009d6d0f, 0x9d5f635b, 0x7e375dbe), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0xb8d1cbd7, 0x33ae8215, 0x642c30af, 0x7cedc7ef, 0x73be8269, 0xfbcc1fb5, 0x44ab3dee, 0xdbea1af4), SECP256K1_FE_CONST(0x945290ca, 0x86af703c, 0x1e0bed9d, 0xf1514972, 0x4357fb2b, 0x8d2382ce, 0x6c2794bf, 0xd14efe9c), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0x472e3428, 0xcc517dea, 0x9bd3cf50, 0x83123810, 0x8c417d96, 0x0433e04a, 0xbb54c210, 0x2415e13b), SECP256K1_FE_CONST(0x6bad6f35, 0x79508fc3, 0xe1f41262, 0x0eaeb68d, 0xbca804d4, 0x72dc7d31, 0x93d86b3f, 0x2eb0fd93)}},
    {0x00, SECP256K1_FE_CONST(0xe52d9c50, 0x8c502347, 0x344d8c07, 0xad91cbd6, 0x068afc75, 0xff6292f0, 0x62a09ca3, 0x81c89e71), SECP256K1_FE_CONST(0x2a58379a, 0x649cd129, 0x3b83c6f8, 0x59fa83fe, 0xa9850a31, 0x5bd1d7aa, 0xfda9b4b3, 0x25e37402), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0x00, SECP256K1_FE_CONST(0x67586e98, 0xfad27da0, 0xb9968bc0, 0x39a1ef34, 0xc939b9b8, 0xe523a8be, 0xf89d4786, 0x08c5ecf6), SECP256K1_FE_CONST(0x98a79167, 0x052d825f, 0x4669743f, 0xc65e10cb, 0x36c64647, 0x1adc5741, 0x0762b878, 0xf73a0f39), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0x00, SECP256K1_FE_CONST(0x67586e98, 0xfad27da0, 0xb9968bc0, 0x39a1ef34, 0xc939b9b8, 0xe523a8be, 0xf89d4786, 0x08c5ecf6), SECP256K1_FE_CONST(0x15a4118b, 0x47af907e, 0xd47bc9cd, 0x722f3641, 0x134228bd, 0x78c1934b, 0x615136f8, 0x3a35675c), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0x44, SECP256K1_FE_CONST(0x01ba4719, 0xc80b6fe9, 0x11b091a7, 0xc05124b6, 0x4eeece96, 0x4e09c058, 0xef8f9805, 0xdaca546b), SECP256K1_FE_CONST(0xbcfa28ac, 0x31453f0e, 0x2ea23512, 0x37dac2de, 0x92e5bbb5, 0xaebfd7bc, 0x3c5a2cae, 0x57c5440f), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0x6fa317d3, 0x93c1632e, 0x73ea7133, 0xb38b0904, 0x670b85c1, 0xf48efa45, 0xcc8c2459, 0xd1463610), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0x905ce82c, 0x6c3e9cd1, 0x8c158ecc, 0x4c74f6fb, 0x98f47a3e, 0x0b7105ba, 0x3373dba5, 0x2eb9c61f), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0xcc, SECP256K1_FE_CONST(0xef6cbd21, 0x61eaea79, 0x43ce8693, 0xb9824d23, 0xd1793ffb, 0x1c0fca05, 0xb600d389, 0x9b44c977), SECP256K1_FE_CONST(0x129374d7, 0x73a60424, 0x662d54d6, 0xe8eba424, 0x38c8c9a7, 0x701a59dc, 0x8fbd0fbb, 0xe6094899), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0x1b65b9d9, 0x1eda84f6, 0x9a068601, 0x70c9c4e9, 0xd43cd0f2, 0x53ec9b13, 0x0f6c2b3d, 0xd949b672), SECP256K1_FE_CONST(0xb5139bd2, 0x4e8e8a6e, 0x5d0875f3, 0x58e3d884, 0xf7f9836d, 0x893fdae8, 0x86cbc6f9, 0x1fd2f993), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0xe49a4626, 0xe1257b09, 0x65f979fe, 0x8f363b16, 0x2bc32f0d, 0xac1364ec, 0xf093d4c1, 0x26b645bd), SECP256K1_FE_CONST(0x4aec642d, 0xb1717591, 0xa2f78a0c, 0xa71c277b, 0x08067c92, 0x76c02517, 0x79343905, 0xe02d029c)}},
    {0x33, SECP256K1_FE_CONST(0xdc0e9c36, 0x58a1a3ed, 0x1ec94274, 0xd8b19925, 0xc93e1abb, 0x7ddba294, 0x923ad9bd, 0xe30f8cb8), SECP256K1_FE_CONST(0x23f163c9, 0xa75e5c12, 0xe136bd8b, 0x274e66da, 0x36c1e544, 0x82245d6b, 0x6dc52641, 0x1cf06f77), {SECP256K1_FE_CONST(0x8245e76e, 0xd8605614, 0xa33447db, 0xdcd4b712, 0x3b80c63f, 0xd0809c87, 0x7b134540, 0x63732da2), SECP256K1_FE_CONST(0x9e474ae5, 0x1714465b, 0x33293068, 0x569fe336, 0x174fb0dc, 0x259049d7, 0x6917ce59, 0x07b6dcff), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0x7dba1891, 0x279fa9eb, 0x5ccbb824, 0x232b48ed, 0xc47f39c0, 0x2f7f6378, 0x84ecbabe, 0x9c8cce8d), SECP256K1_FE_CONST(0x61b8b51a, 0xe8ebb9a4, 0xccd6cf97, 0xa9601cc9, 0xe8b04f23, 0xda6fb628, 0x96e831a5, 0xf8491f30), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0xff, SECP256K1_FE_CONST(0xc555eab4, 0x5d08845a, 0xe9f10d45, 0x2a99bfcb, 0x06f74a50, 0xb988fe7e, 0x48dd3237, 0x89b88ee3), SECP256K1_FE_CONST(0x356b434d, 0x1ef1666c, 0xf7d19635, 0x94a3bdad, 0x982f46ab, 0x3cbdd705, 0x9e1bd9ab, 0x0b7e1686), {SECP256K1_FE_CONST(0x5439b77f, 0x597b2e6f, 0xe48c3f46, 0x599a18fa, 0x0ae89a7a, 0xf778c1dc, 0x886793c8, 0x0fe616ee), SECP256K1_FE_CONST(0xbd6ec9c1, 0x2a329529, 0xf15dfc85, 0xc4526169, 0x5d0767c7, 0x7b4f13ea, 0x91395718, 0x07f3b290), SECP256K1_FE_CONST(0x55715e7f, 0x5d440cc8, 0x3a4010d0, 0x34221026, 0xbcee7131, 0x6217b016, 0xb90dfee7, 0x60a48608), SECP256K1_FE_CONST(0x7e2af404, 0x24b93bf0, 0x1d143213, 0x30df30a2, 0x09678d47, 0xccd5135e, 0x739e4028, 0x26844028), SECP256K1_FE_CONST(0xabc64880, 0xa684d190, 0x1b73c0b9, 0xa665e705, 0xf5176585, 0x08873e23, 0x77986c36, 0xf019e541), SECP256K1_FE_CONST(0x4291363e, 0xd5cd6ad6, 0x0ea2037a, 0x3bad9e96, 0xa2f89838, 0x84b0ec15, 0x6ec6a8e6, 0xf80c499f), SECP256K1_FE_CONST(0xaa8ea180, 0xa2bbf337, 0xc5bfef2f, 0xcbddefd9, 0x43118ece, 0x9de84fe9, 0x46f20117, 0x9f5b7627), SECP256K1_FE_CONST(0x81d50bfb, 0xdb46c40f, 0xe2ebcdec, 0xcf20cf5d, 0xf69872b8, 0x332aeca1, 0x8c61bfd6, 0xd97bbc07)}},
    {0x33, SECP256K1_FE_CONST(0xab897fbd, 0xedfa502b, 0x2d839b6a, 0x56100887, 0xdccdc507, 0x555c282e, 0x59589e06, 0x300a62e2), SECP256K1_FE_CONST(0x3119ceb1, 0xe5e26b7b, 0x1a85520b, 0xaec3ad2c, 0x5661a453, 0xec37f4c6, 0xfae6be04, 0x905fed19), {SECP256K1_FE_CONST(0xa7698f80, 0xa9f7d4f1, 0x4973086b, 0x258934fb, 0x85f056a1, 0xcc824068, 0x70555d65, 0xa5c77c9d), SECP256K1_FE_CONST(0xf5284d8f, 0xc6ee63f5, 0x9511b121, 0xf4fb6105, 0x11b38678, 0x577a2a74, 0xe151f484, 0xfa980ce7), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0x5896707f, 0x56082b0e, 0xb68cf794, 0xda76cb04, 0x7a0fa95e, 0x337dbf97, 0x8faaa299, 0x5a387f92), SECP256K1_FE_CONST(0x0ad7b270, 0x39119c0a, 0x6aee4ede, 0x0b049efa, 0xee4c7987, 0xa885d58b, 0x1eae0b7a, 0x0567ef48), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0x00, SECP256K1_FE_CONST(0xbd4fc42a, 0x21f1f860, 0xa1030e6e, 0xba23d53e, 0xcab71bd1, 0x9297ab6c, 0x074381d4, 0xecee0018), SECP256K1_FE_CONST(0x503cffcb, 0xc1e36f3c, 0x517b387a, 0xd7cbc856, 0x576627d1, 0x4c500c68, 0x33d17039, 0xbb652c96), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}},
    {0xcc, SECP256K1_FE_CONST(0x8a331fdd, 0xe7032f33, 0xa71e1b2e, 0x257d8016, 0x6e348e00, 0xfcb17914, 0xf48bdb57, 0xa1c63007), SECP256K1_FE_CONST(0x5796039b, 0xb8d1bc43, 0x7e7be940, 0x5259919f, 0xc3436f9c, 0xcfd03f91, 0x4c655809, 0x066c7412), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0xf4ec92d2, 0xa1c536c0, 0x3ec32f1b, 0x189f29a2, 0x928ca492, 0x00e81d6e, 0x3e21d469, 0x5458ce50), SECP256K1_FE_CONST(0xf746d123, 0x702173df, 0x05b05807, 0x67a764fe, 0x71c5d1dc, 0xb9aba858, 0xa862814f, 0xa31faf3d), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0x0b136d2d, 0x5e3ac93f, 0xc13cd0e4, 0xe760d65d, 0x6d735b6d, 0xff17e291, 0xc1de2b95, 0xaba72ddf), SECP256K1_FE_CONST(0x08b92edc, 0x8fde8c20, 0xfa4fa7f8, 0x98589b01, 0x8e3a2e23, 0x465457a7, 0x579d7eaf, 0x5ce04cf2)}},
    {0xff, SECP256K1_FE_CONST(0x8a5edab2, 0x82632443, 0x219e051e, 0x4ade2d1d, 0x5bbc671c, 0x781051bf, 0x1437897c, 0xbdfea0f1), SECP256K1_FE_CONST(0x75a1254d, 0x7d9cdbbc, 0xde61fae1, 0xb521d2e2, 0xa44398e3, 0x87efae40, 0xebc87682, 0x42015b3e), {SECP256K1_FE_CONST(0xd7a081ca, 0xf5521f4d, 0xb4f7c478, 0x35ab68a8, 0x217980e6, 0xdad52704, 0xc70b9ba2, 0x14ee14b0), SECP256K1_FE_CONST(0x195dcf2d, 0xa9578581, 0xefa8f64c, 0xa9d6ed4b, 0x8d95e4d0, 0x058fec92, 0x789ad40d, 0xa38c63bb), SECP256K1_FE_CONST(0x52235236, 0x41d891c9, 0x536b9668, 0x46f2af60, 0x028fbd88, 0xac20cad5, 0xc6890a04, 0x886ccc5b), SECP256K1_FE_CONST(0x84e5bc30, 0x521d45e4, 0x0783f049, 0x740067b1, 0x57bfb6d7, 0x71484329, 0x6daba2c9, 0xfc8949fd), SECP256K1_FE_CONST(0x285f7e35, 0x0aade0b2, 0x4b083b87, 0xca549757, 0xde867f19, 0x252ad8fb, 0x38f4645c, 0xeb11e77f), SECP256K1_FE_CONST(0xe6a230d2, 0x56a87a7e, 0x105709b3, 0x562912b4, 0x726a1b2f, 0xfa70136d, 0x87652bf1, 0x5c739874), SECP256K1_FE_CONST(0xaddcadc9, 0xbe276e36, 0xac946997, 0xb90d509f, 0xfd704277, 0x53df352a, 0x3976f5fa, 0x77932fd4), SECP256K1_FE_CONST(0x7b1a43cf, 0xade2ba1b, 0xf87c0fb6, 0x8bff984e, 0xa8404928, 0x8eb7bcd6, 0x92545d35, 0x0376b232)}},
    {0x00, SECP256K1_FE_CONST(0xe7f6c011, 0x776e8db7, 0xcd330b54, 0x174fd76f, 0x7d0216b6, 0x12387a5f, 0xfcfb81e6, 0xf0919683), SECP256K1_FE_CONST(0x2838007a, 0x22e59acb, 0xe2f7e413, 0xd2327157, 0x1c83200f, 0xca4a029d, 0x5b84990f, 0xc3b96177), {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)}}
};

/** This is a hasher for ellswift_xdh which just returns the shared X coordinate.
 *
 * This is generally a bad idea as it means changes to the encoding of the
 * exchanged public keys do not affect the shared secret. However, it's used here
 * in tests to be able to verify the X coordinate through other means.
 */
static int ellswift_xdh_hash_x32(unsigned char *output, const unsigned char *x32, const unsigned char *ours64, const unsigned char *theirs64, void *data) {
    (void)ours64;
    (void)theirs64;
    (void)data;
    memcpy(output, x32, 32);
    return 1;
}

void run_ellswift_tests(void) {
    int i = 0;
    /* Test vectors. */
    for (i = 0; (unsigned)i < sizeof(ellswift_tests) / sizeof(ellswift_tests[0]); ++i) {
        const struct ellswift_test_vec* testcase = &ellswift_tests[i];
        int c;
        for (c = 0; c < 8; ++c) {
            secp256k1_fe t;
            int ret = secp256k1_ellswift_fegex_to_fe_var(&t, &testcase->x, &testcase->u, c);
            CHECK(ret == ((testcase->enc_bitmap >> c) & 1));
            if (ret) {
                secp256k1_fe x2;
                CHECK(check_fe_equal(&t, &testcase->encs[c]));
                secp256k1_ellswift_fe2_to_gex_var(&x2, &testcase->u, &testcase->encs[c]);
                CHECK(check_fe_equal(&testcase->x, &x2));
            }
        }
    }
    /* Verify that secp256k1_ellswift_encode + decode roundtrips. */
    for (i = 0; i < 1000 * count; i++) {
        unsigned char rnd32[32];
        unsigned char ell64[64];
        secp256k1_ge g, g2;
        secp256k1_pubkey pubkey, pubkey2;
        /* Generate random public key and random randomizer. */
        random_group_element_test(&g);
        secp256k1_pubkey_save(&pubkey, &g);
        secp256k1_testrand256(rnd32);
        /* Convert the public key to ElligatorSwift and back. */
        secp256k1_ellswift_encode(ctx, ell64, &pubkey, rnd32);
        secp256k1_ellswift_decode(ctx, &pubkey2, ell64);
        secp256k1_pubkey_load(ctx, &g2, &pubkey2);
        /* Compare with original. */
        ge_equals_ge(&g, &g2);
    }
    /* Verify the behavior of secp256k1_ellswift_create */
    for (i = 0; i < 400 * count; i++) {
        unsigned char rnd32[32], sec32[32];
        secp256k1_scalar sec;
        secp256k1_gej res;
        secp256k1_ge dec;
        secp256k1_pubkey pub;
        unsigned char ell64[64];
        int ret;
        /* Generate random secret key and random randomizer. */
        secp256k1_testrand256_test(rnd32);
        random_scalar_order_test(&sec);
        secp256k1_scalar_get_b32(sec32, &sec);
        /* Construct ElligatorSwift-encoded public keys for that key. */
        ret = secp256k1_ellswift_create(ctx, ell64, sec32, rnd32);
        CHECK(ret);
        /* Decode it, and compare with traditionally-computed public key. */
        secp256k1_ellswift_decode(ctx, &pub, ell64);
        secp256k1_pubkey_load(ctx, &dec, &pub);
        secp256k1_ecmult(&res, NULL, &secp256k1_scalar_zero, &sec);
        ge_equals_gej(&dec, &res);
    }
    /* Verify that secp256k1_ellswift_xdh computes the right shared X coordinate. */
    for (i = 0; i < 800 * count; i++) {
        unsigned char ell64[64], sec32[32], share32[32];
        secp256k1_scalar sec;
        secp256k1_ge dec, res;
        secp256k1_fe share_x;
        secp256k1_gej decj, resj;
        secp256k1_pubkey pub;
        int ret;
        /* Generate random secret key. */
        random_scalar_order_test(&sec);
        secp256k1_scalar_get_b32(sec32, &sec);
        /* Generate random ElligatorSwift encoding for the remote key and decode it. */
        secp256k1_testrand256_test(ell64);
        secp256k1_testrand256_test(ell64 + 32);
        secp256k1_ellswift_decode(ctx, &pub, ell64);
        secp256k1_pubkey_load(ctx, &dec, &pub);
        secp256k1_gej_set_ge(&decj, &dec);
        /* Compute the X coordinate of seckey*pubkey using ellswift_xdh. Note that we
         * pass ell64 as claimed (but incorrect) encoding for sec32 here; this works
         * because the "hasher" function we use here ignores the ours64 argument. */
        ret = secp256k1_ellswift_xdh(ctx, share32, ell64, ell64, sec32, &ellswift_xdh_hash_x32, NULL);
        CHECK(ret);
        secp256k1_fe_set_b32(&share_x, share32);
        /* Compute seckey*pubkey directly. */
        secp256k1_ecmult(&resj, &decj, &sec, NULL);
        secp256k1_ge_set_gej(&res, &resj);
        /* Compare. */
        CHECK(check_fe_equal(&res.x, &share_x));
    }
    /* Verify the joint behavior of secp256k1_ellswift_xdh */
    for (i = 0; i < 200 * count; i++) {
        unsigned char rnd32a[32], rnd32b[32], sec32a[32], sec32b[32];
        secp256k1_scalar seca, secb;
        unsigned char ell64a[64], ell64b[64];
        unsigned char share32a[32], share32b[32];
        int ret;
        /* Generate random secret keys and random randomizers. */
        secp256k1_testrand256_test(rnd32a);
        secp256k1_testrand256_test(rnd32b);
        random_scalar_order_test(&seca);
        random_scalar_order_test(&secb);
        secp256k1_scalar_get_b32(sec32a, &seca);
        secp256k1_scalar_get_b32(sec32b, &secb);
        /* Construct ElligatorSwift-encoded public keys for those keys. */
        ret = secp256k1_ellswift_create(ctx, ell64a, sec32a, rnd32a);
        CHECK(ret);
        ret = secp256k1_ellswift_create(ctx, ell64b, sec32b, rnd32b);
        CHECK(ret);
        /* Compute the shared secret both ways and compare with each other. */
        ret = secp256k1_ellswift_xdh(ctx, share32a, ell64a, ell64b, sec32b, NULL, NULL);
        CHECK(ret);
        ret = secp256k1_ellswift_xdh(ctx, share32b, ell64b, ell64a, sec32a, NULL, NULL);
        CHECK(ret);
        CHECK(secp256k1_memcmp_var(share32a, share32b, 32) == 0);
        /* Verify that the shared secret doesn't match if a secret key or remote pubkey changes. */
        secp256k1_testrand_flip(ell64a, 64);
        ret = secp256k1_ellswift_xdh(ctx, share32a, ell64a, ell64b, sec32b, NULL, NULL);
        CHECK(ret);
        CHECK(secp256k1_memcmp_var(share32a, share32b, 32) != 0);
        secp256k1_testrand_flip(sec32a, 32);
        ret = secp256k1_ellswift_xdh(ctx, share32a, ell64a, ell64b, sec32b, NULL, NULL);
        CHECK(!ret || secp256k1_memcmp_var(share32a, share32b, 32) != 0);
    }
}

#endif
