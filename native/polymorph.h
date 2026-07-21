#pragma once
// Seed: 0x18c43b2f586e0f9c

#define POLY_XOR_KEY1 0xb5a8b483u
#define POLY_XOR_KEY2 0x3c2aa52au

#define POLY_MAGIC1 0xc99efae0u
#define POLY_MAGIC2 0xfac57f15u
#define POLY_MAGIC3 0x74db90abu

#define poly_delay() do { \
    volatile unsigned int mqaham_0 = 0xd6664334u; \
    volatile unsigned int snwohc_1 = 0x7a4c05dbu; \
    volatile unsigned int uuwrla_2 = 0x83c43cc2u; \
    volatile unsigned long long nvzntkyo = 0; \
    for (unsigned long long _i = 0; _i < 53ull; _i++) { \
        nvzntkyo ^= _i ^ 0x37dc73dbu; \
    } \
    (void)nvzntkyo; \
} while(0)

#define poly_mutate() do { \
    volatile unsigned int axdbr = 0xd2bd5b00u; \
    axdbr = axdbr - 0xfe42e1b6u; \
    (void)axdbr; \
    volatile unsigned int zqefz = 0xc6f1f194u; \
    zqefz = zqefz ^ 0xc5dcf777u; \
    (void)zqefz; \
    volatile unsigned int rbklj = 0xb4748fffu; \
    rbklj = rbklj & 0x07807920u; \
    (void)rbklj; \
    volatile unsigned int ipfzb = 0x003b20d3u; \
    ipfzb = ipfzb | 0x0e4d0252u; \
    (void)ipfzb; \
} while(0)

