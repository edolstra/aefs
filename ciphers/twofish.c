/* $Id: twofish.c,v 1.5 2001/09/23 13:30:09 eelco Exp $ */

/* This is an independent implementation of the encryption algorithm:   */
/*                                                                      */
/*         Twofish by Bruce Schneier and colleagues                     */
/*                                                                      */
/* which is a candidate algorithm in the Advanced Encryption Standard   */
/* programme of the US National Institute of Standards and Technology.  */
/*                                                                      */
/* Copyright in this implementation is held by Dr B R Gladman but I     */
/* hereby give permission for its free direct or derivative use subject */
/* to acknowledgment of its origin and compliance with any conditions   */
/* that the originators of the algorithm place on its exploitation.     */
/*                                                                      */
/* My thanks to Doug Whiting and Niels Ferguson for comments that led   */
/* to improvements in this implementation.                              */
/*                                                                      */
/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 14th January 1999     */

/* Timing data for Twofish (twofish.c)

128 bit key:
Key Setup:    8414 cycles
Encrypt:       376 cycles =    68.1 mbits/sec
Decrypt:       374 cycles =    68.4 mbits/sec
Mean:          375 cycles =    68.3 mbits/sec

192 bit key:
Key Setup:   11628 cycles
Encrypt:       376 cycles =    68.1 mbits/sec
Decrypt:       374 cycles =    68.4 mbits/sec
Mean:          375 cycles =    68.3 mbits/sec

256 bit key:
Key Setup:   15457 cycles
Encrypt:       381 cycles =    67.2 mbits/sec
Decrypt:       374 cycles =    68.4 mbits/sec
Mean:          378 cycles =    67.8 mbits/sec

*/

#include "sysdep.h"
#include "cipher.h"

typedef uint8  u1byte; /* an 8 bit unsigned character type */
typedef uint32 u4byte; /* a 32 bit unsigned integer type   */

#define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
#define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))

#define byte(x,n)   ((u1byte)((x) >> (8 * n)))

#ifdef WORDS_BIGENDIAN
static inline u4byte swap(u4byte x)
{
    return 
        (x >> 24) |
        ((x >> 8) & (0x0000ff00)) |
        ((x << 8) & (0x00ff0000)) |
        (x << 24);
}
#else
#define swap(x) (x)
#endif

typedef struct {
        u4byte  k_len;
        u4byte  l_key[40];
        u4byte  s_key[4];
        u4byte  mk_tab[4][256];
} KeyData;

/* finite field arithmetic for GF(2**8) with the modular    */
/* polynomial x^8 + x^6 + x^5 + x^3 + 1 (0x169)             */

#define G_M 0x0169

static u1byte  tab_5b[4] = { 0, G_M >> 2, G_M >> 1, (G_M >> 1) ^ (G_M >> 2) };
static u1byte  tab_ef[4] = { 0, (G_M >> 1) ^ (G_M >> 2), G_M >> 1, G_M >> 2 };

#define ffm_01(x)    (x)
#define ffm_5b(x)   ((x) ^ ((x) >> 2) ^ tab_5b[(x) & 3])
#define ffm_ef(x)   ((x) ^ ((x) >> 1) ^ ((x) >> 2) ^ tab_ef[(x) & 3])

static u1byte ror4[16] = { 0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15 };
static u1byte ashx[16] = { 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7 };

static u1byte qt0[2][16] = 
{   { 8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4 },
    { 2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5 }
};

static u1byte qt1[2][16] =
{   { 14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13 }, 
    { 1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8 }
};

static u1byte qt2[2][16] = 
{   { 11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1 },
    { 4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15 }
};

static u1byte qt3[2][16] = 
{   { 13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10 },
    { 11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10 }
};
 
u1byte qp(const u4byte n, const u1byte x)
{   u1byte  a0, a1, a2, a3, a4, b0, b1, b2, b3, b4;

    a0 = x >> 4; b0 = x & 15;
    a1 = a0 ^ b0; b1 = ror4[b0] ^ ashx[a0];
    a2 = qt0[n][a1]; b2 = qt1[n][b1];
    a3 = a2 ^ b2; b3 = ror4[b2] ^ ashx[a2];
    a4 = qt2[n][a3]; b4 = qt3[n][b3];
    return (b4 << 4) | a4;
}

static u4byte  qt_gen = 0;
static u1byte  q_tab[2][256];

#define q(n,x)  q_tab[n][x]

static void gen_qtab(void)
{   u4byte  i;

    for(i = 0; i < 256; ++i)
    {       
        q(0,i) = qp(0, (u1byte)i);
        q(1,i) = qp(1, (u1byte)i);
    }
}

static u4byte  mt_gen = 0;
static u4byte  m_tab[4][256];

static void gen_mtab(void)
{   u4byte  i, f01, f5b, fef;
    
    for(i = 0; i < 256; ++i)
    {
        f01 = q(1,i); f5b = ffm_5b(f01); fef = ffm_ef(f01);
        m_tab[0][i] = f01 + (f5b << 8) + (fef << 16) + (fef << 24);
        m_tab[2][i] = f5b + (fef << 8) + (f01 << 16) + (fef << 24);

        f01 = q(0,i); f5b = ffm_5b(f01); fef = ffm_ef(f01);
        m_tab[1][i] = fef + (fef << 8) + (f5b << 16) + (f01 << 24);
        m_tab[3][i] = f5b + (f01 << 8) + (fef << 16) + (f5b << 24);
    }
}

#define mds(n,x)    m_tab[n][x]

static u4byte h_fun(int k_len, const u4byte x, const u4byte key[])
{   u4byte  b0, b1, b2, b3;

    b0 = byte(x, 0); b1 = byte(x, 1); b2 = byte(x, 2); b3 = byte(x, 3);

    switch(k_len)
    {
    case 4: b0 = q(1, b0) ^ byte(key[3],0);
            b1 = q(0, b1) ^ byte(key[3],1);
            b2 = q(0, b2) ^ byte(key[3],2);
            b3 = q(1, b3) ^ byte(key[3],3);
    case 3: b0 = q(1, b0) ^ byte(key[2],0);
            b1 = q(1, b1) ^ byte(key[2],1);
            b2 = q(0, b2) ^ byte(key[2],2);
            b3 = q(0, b3) ^ byte(key[2],3);
    case 2: b0 = q(0,q(0,b0) ^ byte(key[1],0)) ^ byte(key[0],0);
            b1 = q(0,q(1,b1) ^ byte(key[1],1)) ^ byte(key[0],1);
            b2 = q(1,q(0,b2) ^ byte(key[1],2)) ^ byte(key[0],2);
            b3 = q(1,q(1,b3) ^ byte(key[1],3)) ^ byte(key[0],3);
    }

    return  mds(0, b0) ^ mds(1, b1) ^ mds(2, b2) ^ mds(3, b3);
}

#define q20(x)  q(0,q(0,x) ^ byte(key->s_key[1],0)) ^ byte(key->s_key[0],0)
#define q21(x)  q(0,q(1,x) ^ byte(key->s_key[1],1)) ^ byte(key->s_key[0],1)
#define q22(x)  q(1,q(0,x) ^ byte(key->s_key[1],2)) ^ byte(key->s_key[0],2)
#define q23(x)  q(1,q(1,x) ^ byte(key->s_key[1],3)) ^ byte(key->s_key[0],3)

#define q30(x)  q(0,q(0,q(1, x) ^ byte(key->s_key[2],0)) ^ byte(key->s_key[1],0)) ^ byte(key->s_key[0],0)
#define q31(x)  q(0,q(1,q(1, x) ^ byte(key->s_key[2],1)) ^ byte(key->s_key[1],1)) ^ byte(key->s_key[0],1)
#define q32(x)  q(1,q(0,q(0, x) ^ byte(key->s_key[2],2)) ^ byte(key->s_key[1],2)) ^ byte(key->s_key[0],2)
#define q33(x)  q(1,q(1,q(0, x) ^ byte(key->s_key[2],3)) ^ byte(key->s_key[1],3)) ^ byte(key->s_key[0],3)

#define q40(x)  q(0,q(0,q(1, q(1, x) ^ byte(key->s_key[3],0)) ^ byte(key->s_key[2],0)) ^ byte(key->s_key[1],0)) ^ byte(key->s_key[0],0)
#define q41(x)  q(0,q(1,q(1, q(0, x) ^ byte(key->s_key[3],1)) ^ byte(key->s_key[2],1)) ^ byte(key->s_key[1],1)) ^ byte(key->s_key[0],1)
#define q42(x)  q(1,q(0,q(0, q(0, x) ^ byte(key->s_key[3],2)) ^ byte(key->s_key[2],2)) ^ byte(key->s_key[1],2)) ^ byte(key->s_key[0],2)
#define q43(x)  q(1,q(1,q(0, q(1, x) ^ byte(key->s_key[3],3)) ^ byte(key->s_key[2],3)) ^ byte(key->s_key[1],3)) ^ byte(key->s_key[0],3)

void static gen_mk_tab(KeyData * key)
{   u4byte  i;
    u1byte  by;

    switch(key->k_len)
    {
    case 2: for(i = 0; i < 256; ++i)
            {
                by = (u1byte)i;
                key->mk_tab[0][i] = mds(0, q20(by)); key->mk_tab[1][i] = mds(1, q21(by));
                key->mk_tab[2][i] = mds(2, q22(by)); key->mk_tab[3][i] = mds(3, q23(by));
            }
            break;
    
    case 3: for(i = 0; i < 256; ++i)
            {
                by = (u1byte)i;
                key->mk_tab[0][i] = mds(0, q30(by)); key->mk_tab[1][i] = mds(1, q31(by));
                key->mk_tab[2][i] = mds(2, q32(by)); key->mk_tab[3][i] = mds(3, q33(by));
            }
            break;
    
    case 4: for(i = 0; i < 256; ++i)
            {
                by = (u1byte)i;
                key->mk_tab[0][i] = mds(0, q40(by)); key->mk_tab[1][i] = mds(1, q41(by));
                key->mk_tab[2][i] = mds(2, q42(by)); key->mk_tab[3][i] = mds(3, q43(by));
            }
    }
}

#    define g0_fun(x) ( key->mk_tab[0][byte(x,0)] ^ key->mk_tab[1][byte(x,1)] \
                      ^ key->mk_tab[2][byte(x,2)] ^ key->mk_tab[3][byte(x,3)] )
#    define g1_fun(x) ( key->mk_tab[0][byte(x,3)] ^ key->mk_tab[1][byte(x,0)] \
                      ^ key->mk_tab[2][byte(x,1)] ^ key->mk_tab[3][byte(x,2)] )

/* The (12,8) Reed Soloman code has the generator polynomial

  g(x) = x^4 + (a + 1/a) * x^3 + a * x^2 + (a + 1/a) * x + 1

where the coefficients are in the finite field GF(2^8) with a
modular polynomial a^8 + a^6 + a^3 + a^2 + 1. To generate the
remainder we have to start with a 12th order polynomial with our
eight input bytes as the coefficients of the 4th to 11th terms. 
That is:

  m[7] * x^11 + m[6] * x^10 ... + m[0] * x^4 + 0 * x^3 +... + 0
  
We then multiply the generator polynomial by m[7] * x^7 and subtract
it - xor in GF(2^8) - from the above to eliminate the x^7 term (the 
artihmetic on the coefficients is done in GF(2^8). We then multiply 
the generator polynomial by x^6 * coeff(x^10) and use this to remove
the x^10 term. We carry on in this way until the x^4 term is removed
so that we are left with:

  r[3] * x^3 + r[2] * x^2 + r[1] 8 x^1 + r[0]

which give the resulting 4 bytes of the remainder. This is equivalent 
to the matrix multiplication in the Twofish description but much faster 
to implement.

*/

#define G_MOD   0x0000014d

static u4byte mds_rem(u4byte p0, u4byte p1)
{   u4byte  i, t, u;

    for(i = 0; i < 8; ++i)
    {
        t = p1 >> 24;   /* get most significant coefficient */
        
        p1 = (p1 << 8) | (p0 >> 24); p0 <<= 8;  /* shift others up */
            
        /* multiply t by a (the primitive element - i.e. left shift) */

        u = (t << 1); 
        
        if(t & 0x80)   /* subtract modular polynomial on overflow */
        
            u ^= G_MOD; 

        p1 ^= t ^ (u << 16);    /* remove t * (a * x^2 + 1) */

        u ^= (t >> 1); /* form u = a * t + t / a = t * (a + 1 / a); */
        
        if(t & 0x01) /* add the modular polynomial on underflow */
        
            u ^= G_MOD >> 1;

        p1 ^= (u << 24) | (u << 8); /* remove t * (a + 1/a) * (x^3 + x) */
    }

    return p1;
}

/* initialise the key schedule from the user supplied key   */

static void set_key(KeyData * key, const u4byte in_key[],
    const u4byte key_len)
{   u4byte  i, a, b, me_key[4], mo_key[4];

    if(!qt_gen)
    {
        gen_qtab(); qt_gen = 1;
    }

    if(!mt_gen)
    {
        gen_mtab(); mt_gen = 1;
    }

    key->k_len = key_len / 64;   /* 2, 3 or 4 */

    for(i = 0; i < key->k_len; ++i)
    {
        a = swap(in_key[i + i]);     me_key[i] = a;
        b = swap(in_key[i + i + 1]); mo_key[i] = b;
        key->s_key[key->k_len - i - 1] = mds_rem(a, b);
    }

    for(i = 0; i < 40; i += 2)
    {
        a = 0x01010101 * i; b = a + 0x01010101;
        a = h_fun(key->k_len, a, me_key);
        b = rotl(h_fun(key->k_len, b, mo_key), 8);
        key->l_key[i] = a + b;
        key->l_key[i + 1] = rotl(a + 2 * b, 9);
    }

    gen_mk_tab(key);
}

/* encrypt a block of text  */

#define f_rnd(i)                                                    \
    t1 = g1_fun(blk[1]); t0 = g0_fun(blk[0]);                       \
    blk[2] = rotr(blk[2] ^ (t0 + t1 + key->l_key[4 * (i) + 8]), 1);      \
    blk[3] = rotl(blk[3], 1) ^ (t0 + 2 * t1 + key->l_key[4 * (i) + 9]);  \
    t1 = g1_fun(blk[3]); t0 = g0_fun(blk[2]);                       \
    blk[0] = rotr(blk[0] ^ (t0 + t1 + key->l_key[4 * (i) + 10]), 1);     \
    blk[1] = rotl(blk[1], 1) ^ (t0 + 2 * t1 + key->l_key[4 * (i) + 11])

static void twofishEncryptBlock(Key * pKey, octet * pabBlock)
{   u4byte  t0, t1, blk[4];
    KeyData * key = pKey->pExpandedKey;

    blk[0] = swap(0[(u4byte *) pabBlock]) ^ key->l_key[0];
    blk[1] = swap(1[(u4byte *) pabBlock]) ^ key->l_key[1];
    blk[2] = swap(2[(u4byte *) pabBlock]) ^ key->l_key[2];
    blk[3] = swap(3[(u4byte *) pabBlock]) ^ key->l_key[3];

    f_rnd(0); f_rnd(1); f_rnd(2); f_rnd(3);
    f_rnd(4); f_rnd(5); f_rnd(6); f_rnd(7);

    0[(u4byte *) pabBlock] = swap(blk[2] ^ key->l_key[4]);
    1[(u4byte *) pabBlock] = swap(blk[3] ^ key->l_key[5]);
    2[(u4byte *) pabBlock] = swap(blk[0] ^ key->l_key[6]);
    3[(u4byte *) pabBlock] = swap(blk[1] ^ key->l_key[7]); 
}

/* decrypt a block of text  */

#define i_rnd(i)                                                        \
        t1 = g1_fun(blk[1]); t0 = g0_fun(blk[0]);                       \
        blk[2] = rotl(blk[2], 1) ^ (t0 + t1 + key->l_key[4 * (i) + 10]);     \
        blk[3] = rotr(blk[3] ^ (t0 + 2 * t1 + key->l_key[4 * (i) + 11]), 1); \
        t1 = g1_fun(blk[3]); t0 = g0_fun(blk[2]);                       \
        blk[0] = rotl(blk[0], 1) ^ (t0 + t1 + key->l_key[4 * (i) +  8]);     \
        blk[1] = rotr(blk[1] ^ (t0 + 2 * t1 + key->l_key[4 * (i) +  9]), 1)

static void twofishDecryptBlock(Key * pKey, octet * pabBlock)
{   u4byte  t0, t1, blk[4];
    KeyData * key = pKey->pExpandedKey;

    blk[0] = swap(0[(u4byte *) pabBlock]) ^ key->l_key[4];
    blk[1] = swap(1[(u4byte *) pabBlock]) ^ key->l_key[5];
    blk[2] = swap(2[(u4byte *) pabBlock]) ^ key->l_key[6];
    blk[3] = swap(3[(u4byte *) pabBlock]) ^ key->l_key[7];

    i_rnd(7); i_rnd(6); i_rnd(5); i_rnd(4);
    i_rnd(3); i_rnd(2); i_rnd(1); i_rnd(0);

    0[(u4byte *) pabBlock] = swap(blk[2] ^ key->l_key[0]);
    1[(u4byte *) pabBlock] = swap(blk[3] ^ key->l_key[1]);
    2[(u4byte *) pabBlock] = swap(blk[0] ^ key->l_key[2]);
    3[(u4byte *) pabBlock] = swap(blk[1] ^ key->l_key[3]); 
}


static CipherResult twofishExpandKey(Key * pKey)
{
    KeyData * key;

    if (pKey->cbBlock != 16)
        return CIPHERRC_INVALID_BLOCKSIZE;
    if (pKey->cbKey != 16 && pKey->cbKey != 24 && pKey->cbKey != 32)
        return CIPHERRC_INVALID_KEYSIZE;

    key = sysAllocSecureMem(sizeof(KeyData));
    if (!key) return CIPHERRC_NOT_ENOUGH_MEMORY;

    set_key(key, (u4byte *) pKey->pabKey, pKey->cbKey * 8);

    pKey->pExpandedKey = (void *) key;

    return CIPHERRC_OK;
}


static void twofishFreeExpandedKey(Key * pKey)
{
    sysFreeSecureMem(pKey->pExpandedKey);
    pKey->pExpandedKey = 0;
}


static CipherSize aTwofishSizes[] = {
    { 16, 16 },
    { 16, 24 },
    { 16, 32 },
    { 0, 0 }
};

Cipher cipherTwofish =
{
    "twofish",
    "Twofish block cipher",
    aTwofishSizes,
    twofishExpandKey,
    twofishFreeExpandedKey,
    twofishEncryptBlock,
    twofishDecryptBlock
};
