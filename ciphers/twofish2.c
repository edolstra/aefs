/* Modified for AEFS by Eelco Dolstra (edolstra@students.cs.uu.nl). */

/***************************************************************************
    TWOFISH.C   -- C API calls for TWOFISH AES submission

    Submitters:
        Bruce Schneier, Counterpane Systems
        Doug Whiting,   Hi/fn
        John Kelsey,    Counterpane Systems
        Chris Hall,     Counterpane Systems
        David Wagner,   UC Berkeley
            
    Code Author:        Doug Whiting,   Hi/fn
        
    Version  1.00       April 1998
        
    Copyright 1998, Hi/fn and Counterpane Systems.  All rights reserved.
        
    Notes:
        *   Optimized version
        *   Tab size is set to 4 characters in this file

***************************************************************************/

#include "twofish.h"
#include "sysdep.h"

#include "std_defs.h"

/* Things from platform.h. */

#define LittleEndian 1

#if LittleEndian
#define     Bswap(x)            (x)     /* NOP for little-endian machines */
#define     ADDR_XOR            0       /* NOP for little-endian machines */
#else
#define     Bswap(x)            ((ROR(x,8) & 0xFF00FF00) | (ROL(x,8) & 0x00FF00FF))
#define     ADDR_XOR            3       /* convert byte address in dword */
#endif

/*  Macros for extracting bytes from dwords (correct for endianness) */
#define _b(x,N) (((BYTE *)&x)[((N) & 3) ^ ADDR_XOR]) /* pick bytes out of a dword */

#define     b0(x)           _b(x,0)     /* extract LSB of DWORD */
#define     b1(x)           _b(x,1)
#define     b2(x)           _b(x,2)
#define     b3(x)           _b(x,3)     /* extract MSB of DWORD */


/* Things from aes.h. */

#define     TRUE            1
#define     FALSE           0

#define     BLOCK_SIZE          128 /* number of bits per block */
#define     MAX_ROUNDS           16 /* max # rounds (for allocating subkey array) */
#define     ROUNDS_128           16 /* default number of rounds for 128-bit keys*/
#define     ROUNDS_192           16 /* default number of rounds for 192-bit keys*/
#define     ROUNDS_256           16 /* default number of rounds for 256-bit keys*/
#define     MAX_KEY_BITS        256 /* max number of bits of key */
#define     MIN_KEY_BITS        128 /* min number of bits of key (zero pad) */

#define     INPUT_WHITEN        0   /* subkey array indices */
#define     OUTPUT_WHITEN       ( INPUT_WHITEN + BLOCK_SIZE/32)
#define     ROUND_SUBKEYS       (OUTPUT_WHITEN + BLOCK_SIZE/32) /* use 2 * (# rounds) */
#define     TOTAL_SUBKEYS       (ROUND_SUBKEYS + 2*MAX_ROUNDS)

/* Typedefs:
    Typedef'ed data storage elements. Add any algorithm specific
    parameters at the bottom of the structs as appropriate.
*/

typedef unsigned char BYTE;
typedef unsigned long DWORD;        /* 32-bit unsigned quantity */
typedef DWORD fullSbox[4][256];

/* The structure for key information */
typedef struct 
    {
    /* Twofish-specific parameters: */
    DWORD subKeys[TOTAL_SUBKEYS];   /* round subkeys, input/output whitening bits */
    DWORD subKeys2[TOTAL_SUBKEYS];  /* subKeys -> decrypt,
                                       subKeys2 -> encrypt */
    fullSbox sBox8x32;              /* fully expanded S-box */
    } KeyData;

#define     CONST               /* helpful C++ syntax sugar, NOP for ANSI C */


/* Things from table.h. */

/* for computing subkeys */
#define SK_STEP         0x02020202u
#define SK_BUMP         0x01010101u
#define SK_ROTL         9

/* Reed-Solomon code parameters: (12,8) reversible code
    g(x) = x**4 + (a + 1/a) x**3 + a x**2 + (a + 1/a) x + 1
   where a = primitive root of field generator 0x14D */
#define RS_GF_FDBK      0x14D       /* field generator */
#define RS_rem(x)       \
    { BYTE  b  =   x >> 24;                                                  \
      DWORD g2 = ((b << 1) ^ ((b & 0x80) ? RS_GF_FDBK : 0 )) & 0xFF;         \
      DWORD g3 = ((b >> 1) & 0x7F) ^ ((b & 1) ? RS_GF_FDBK >> 1 : 0 ) ^ g2 ; \
      x = (x << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b;                \
    }

/*  Macros for the MDS matrix
*   The MDS matrix is (using primitive polynomial 169):
*      01  EF  5B  5B
*      5B  EF  EF  01
*      EF  5B  01  EF
*      EF  01  EF  5B
*----------------------------------------------------------------
* More statistical properties of this matrix (from MDS.EXE output):
*
* Min Hamming weight (one byte difference) =  8. Max=26.  Total =  1020.
* Prob[8]:      7    23    42    20    52    95    88    94   121   128    91
*             102    76    41    24     8     4     1     3     0     0     0
* Runs[8]:      2     4     5     6     7     8     9    11
* MSBs[8]:      1     4    15     8    18    38    40    43
* HW= 8: 05040705 0A080E0A 14101C14 28203828 50407050 01499101 A080E0A0 
* HW= 9: 04050707 080A0E0E 10141C1C 20283838 40507070 80A0E0E0 C6432020 07070504 
*        0E0E0A08 1C1C1410 38382820 70705040 E0E0A080 202043C6 05070407 0A0E080E 
*        141C101C 28382038 50704070 A0E080E0 4320C620 02924B02 089A4508 
* Min Hamming weight (two byte difference) =  3. Max=28.  Total = 390150.
* Prob[3]:      7    18    55   149   270   914  2185  5761 11363 20719 32079
*           43492 51612 53851 52098 42015 31117 20854 11538  6223  2492  1033
* MDS OK, ROR:   6+  7+  8+  9+ 10+ 11+ 12+ 13+ 14+ 15+ 16+
*               17+ 18+ 19+ 20+ 21+ 22+ 23+ 24+ 25+ 26+
*/
#define MDS_GF_FDBK     0x169   /* primitive polynomial for GF(256)*/
#define LFSR1(x) ( ((x) >> 1)  ^ (((x) & 0x01) ?   MDS_GF_FDBK/2 : 0))
#define LFSR2(x) ( ((x) >> 2)  ^ (((x) & 0x02) ?   MDS_GF_FDBK/2 : 0)  \
                               ^ (((x) & 0x01) ?   MDS_GF_FDBK/4 : 0))

#define Mx_1(x) ((DWORD)  (x))      /* force result to dword so << will work */
#define Mx_X(x) ((DWORD) ((x) ^            LFSR2(x)))   /* 5B */
#define Mx_Y(x) ((DWORD) ((x) ^ LFSR1(x) ^ LFSR2(x)))   /* EF */

#define M00     Mul_1
#define M01     Mul_Y
#define M02     Mul_X
#define M03     Mul_X

#define M10     Mul_X
#define M11     Mul_Y
#define M12     Mul_Y
#define M13     Mul_1

#define M20     Mul_Y
#define M21     Mul_X
#define M22     Mul_1
#define M23     Mul_Y

#define M30     Mul_Y
#define M31     Mul_1
#define M32     Mul_Y
#define M33     Mul_X

#define Mul_1   Mx_1
#define Mul_X   Mx_X
#define Mul_Y   Mx_Y

/*  Define the fixed p0/p1 permutations used in keyed S-box lookup.  
    By changing the following constant definitions for P_ij, the S-boxes will
    automatically get changed in all the Twofish source code. Note that P_i0 is
    the "outermost" 8x8 permutation applied.  See the f32() function to see
    how these constants are to be  used.
*/
#define P_00    1                   /* "outermost" permutation */
#define P_01    0
#define P_02    0
#define P_03    (P_01^1)            /* "extend" to larger key sizes */
#define P_04    1

#define P_10    0
#define P_11    0
#define P_12    1
#define P_13    (P_11^1)
#define P_14    0

#define P_20    1
#define P_21    1
#define P_22    0
#define P_23    (P_21^1)
#define P_24    0

#define P_30    0
#define P_31    1
#define P_32    1
#define P_33    (P_31^1)
#define P_34    1

#define p8(N)   P8x8[P_##N]         /* some syntax shorthand */

/* fixed 8x8 permutation S-boxes */

/***********************************************************************
*  07:07:14  05/30/98  [4x4]  TestCnt=256. keySize=128. CRC=4BD14D9E.
* maxKeyed:  dpMax = 18. lpMax =100. fixPt =  8. skXor =  0. skDup =  6. 
* log2(dpMax[ 6..18])=   --- 15.42  1.33  0.89  4.05  7.98 12.05
* log2(lpMax[ 7..12])=  9.32  1.01  1.16  4.23  8.02 12.45
* log2(fixPt[ 0.. 8])=  1.44  1.44  2.44  4.06  6.01  8.21 11.07 14.09 17.00
* log2(skXor[ 0.. 0])
* log2(skDup[ 0.. 6])=   ---  2.37  0.44  3.94  8.36 13.04 17.99
***********************************************************************/
static CONST BYTE P8x8[2][256]=
{
   /*  p0:   */
   /*  dpMax      = 10.  lpMax      = 64.  cycleCnt=   1  1  1  0.         */
   /* 817D6F320B59ECA4.ECB81235F4A6709D.BA5E6D90C8F32471.D7F4126E9B3085CA. */
   /* Karnaugh maps:
    *  0111 0001 0011 1010. 0001 1001 1100 1111. 1001 1110 0011 1110. 1101 0101 1111 1001. 
    *  0101 1111 1100 0100. 1011 0101 0010 0000. 0101 1000 1100 0101. 1000 0111 0011 0010. 
    *  0000 1001 1110 1101. 1011 1000 1010 0011. 0011 1001 0101 0000. 0100 0010 0101 1011. 
    *  0111 0100 0001 0110. 1000 1011 1110 1001. 0011 0011 1001 1101. 1101 0101 0000 1100. 
    */
   {
      0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 
      0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38, 
      0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 
      0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48, 
      0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 
      0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82, 
      0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 
      0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61, 
      0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 
      0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1, 
      0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 
      0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7, 
      0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 
      0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71, 
      0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 
      0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7, 
      0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 
      0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90, 
      0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 
      0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF, 
      0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 
      0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64, 
      0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 
      0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A, 
      0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 
      0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D, 
      0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 
      0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34, 
      0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 
      0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4, 
      0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 
      0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0
   },
   /*  p1:   */
   /*  dpMax      = 10.  lpMax      = 64.  cycleCnt=   2  0  0  1.         */
   /* 28BDF76E31940AC5.1E2B4C376DA5F908.4C75169A0ED82B3F.B951C3DE647F208A. */
   /* Karnaugh maps:
    *  0011 1001 0010 0111. 1010 0111 0100 0110. 0011 0001 1111 0100. 1111 1000 0001 1100. 
    *  1100 1111 1111 1010. 0011 0011 1110 0100. 1001 0110 0100 0011. 0101 0110 1011 1011. 
    *  0010 0100 0011 0101. 1100 1000 1000 1110. 0111 1111 0010 0110. 0000 1010 0000 0011. 
    *  1101 1000 0010 0001. 0110 1001 1110 0101. 0001 0100 0101 0111. 0011 1011 1111 0010. 
    */
   {
      0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 
      0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B, 
      0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 
      0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F, 
      0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 
      0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5, 
      0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 
      0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51, 
      0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 
      0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C, 
      0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 
      0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8, 
      0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 
      0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2, 
      0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 
      0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17, 
      0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 
      0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E, 
      0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 
      0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9, 
      0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 
      0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48, 
      0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 
      0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64, 
      0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 
      0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69, 
      0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 
      0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC, 
      0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 
      0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9, 
      0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 
      0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
   }
};


/*
+*****************************************************************************
*           Constants/Macros/Tables
-****************************************************************************/

static fullSbox MDStab;        /* not actually const.  Initialized ONE time */
static int      needToBuildMDS=1;       /* is MDStab initialized yet? */

/* number of rounds for various key sizes: 128, 192, 256 */
static int  numRounds[4]= {0,ROUNDS_128,ROUNDS_192,ROUNDS_256};

#define     _sBox_   key->sBox8x32
#define _sBox8_(N) (((BYTE *) _sBox_) + (N)*256)

/* Fe32_ does a full S-box + MDS lookup.  Need to #define _sBox_ before use.
   Note that we "interleave" 0,1, and 2,3 to avoid cache bank collisions
   in optimized assembly language.
*/
#define Fe32_(x,R) (_sBox_[0][2*_b(x,R  )] ^ _sBox_[0][2*_b(x,R+1)+1] ^ \
                    _sBox_[2][2*_b(x,R+2)] ^ _sBox_[2][2*_b(x,R+3)+1])
        /* set a single S-box value, given the input byte */
#define sbSet(N,i,J,v) { _sBox_[N&2][2*i+(N&1)+2*J]=MDStab[N][v]; }


/*
+*****************************************************************************
*
* Function Name:    RS_MDS_Encode
*
* Function:         Use (12,8) Reed-Solomon code over GF(256) to produce
*                   a key S-box dword from two key material dwords.
*
* Arguments:        k0  =   1st dword
*                   k1  =   2nd dword
*
* Return:           Remainder polynomial generated using RS code
*
* Notes:
*   Since this computation is done only once per reKey per 64 bits of key,
*   the performance impact of this routine is imperceptible. The RS code
*   chosen has "simple" coefficients to allow smartcard/hardware implementation
*   without lookup tables.
*
-****************************************************************************/
static DWORD RS_MDS_Encode(DWORD k0,DWORD k1)
    {
    int i,j;
    DWORD r;

    for (i=r=0;i<2;i++)
        {
        r ^= (i) ? k0 : k1;         /* merge in 32 more key bits */
        for (j=0;j<4;j++)           /* shift one byte at a time */
            RS_rem(r);              
        }
    return r;
    }


/*
+*****************************************************************************
*
* Function Name:    BuildMDS
*
* Function:         Initialize the MDStab array
*
* Arguments:        None.
*
* Return:           None.
*
* Notes:
*   Here we precompute all the fixed MDS table.  This only needs to be done
*   one time at initialization, after which the table is "CONST".
*
-****************************************************************************/
static void BuildMDS(void)
    {
    int i;
    DWORD d;
    BYTE m1[2],mX[2],mY[2];

    for (i=0;i<256;i++)
        {
        m1[0]=P8x8[0][i];       /* compute all the matrix elements */
        mX[0]=(BYTE) Mul_X(m1[0]);
        mY[0]=(BYTE) Mul_Y(m1[0]);

        m1[1]=P8x8[1][i];
        mX[1]=(BYTE) Mul_X(m1[1]);
        mY[1]=(BYTE) Mul_Y(m1[1]);

#undef  Mul_1                   /* change what the pre-processor does with Mij */
#undef  Mul_X
#undef  Mul_Y
#define Mul_1   m1              /* It will now access m01[], m5B[], and mEF[] */
#define Mul_X   mX              
#define Mul_Y   mY

#define SetMDS(N)                   \
        b0(d) = M0##N[P_##N##0];    \
        b1(d) = M1##N[P_##N##0];    \
        b2(d) = M2##N[P_##N##0];    \
        b3(d) = M3##N[P_##N##0];    \
        MDStab[N][i] = d;

        SetMDS(0);              /* fill in the matrix with elements computed above */
        SetMDS(1);
        SetMDS(2);
        SetMDS(3);
        }
#undef  Mul_1
#undef  Mul_X
#undef  Mul_Y
#define Mul_1   Mx_1            /* re-enable true multiply */
#define Mul_X   Mx_X
#define Mul_Y   Mx_Y
    
    needToBuildMDS=0;           /* NEVER modify the table again! */
    }


/*
+*****************************************************************************
*
* Function Name:    Xor256
*
* Function:         Copy an 8-bit permutation (256 bytes), xoring with a byte
*
* Arguments:        dst     =   where to put result
*                   src     =   where to get data (can be same asa dst)
*                   b       =   byte to xor
*
* Return:           None
*
* Notes:
*   BorlandC's optimization is terrible!  When we put the code inline,
*   it generates fairly good code in the *following* segment (not in the Xor256
*   code itself).  If the call is made, the code following the call is awful!
*   The penalty is nearly 50%!  So we take the code size hit for inlining for
*   Borland, while Microsoft happily works with a call.
*
-****************************************************************************/
#define Xor32(dst,src,i) { ((DWORD *)dst)[i] = ((DWORD *)src)[i] ^ tmpX; } 
#define Xor256(dst,src,b)               \
    {                                   \
    register DWORD tmpX=0x01010101u * b;\
    for (i=0;i<64;i+=4)                 \
        { Xor32(dst,src,i  ); Xor32(dst,src,i+1); Xor32(dst,src,i+2); Xor32(dst,src,i+3); } \
    }


/*
+*****************************************************************************
*
* Function Name:    reKey
*
* Function:         Initialize the Twofish key schedule from key32
*
* Arguments:        key         =   ptr to keyInstance to be initialized
*
* Return:           TRUE on success
*
* Notes:
*   Here we precompute all the round subkeys, although that is not actually
*   required.  For example, on a smartcard, the round subkeys can 
*   be generated on-the-fly using f32()
*
-****************************************************************************/
static int reKey(KeyData * key, int keyLen, DWORD * key32)
    {
    int     i,j,k64Cnt;
    int     subkeyCnt;
    DWORD   A=0,B=0,q;
    DWORD   sKey[MAX_KEY_BITS/64],k32e[MAX_KEY_BITS/64],k32o[MAX_KEY_BITS/64];
    BYTE    L0[256],L1[256];    /* small local 8-bit permutations */
    DWORD t0,t1;
    int rounds;
    register DWORD *r0;
    register DWORD *r1;

    if (needToBuildMDS)         /* do this one time only */
        BuildMDS();

   rounds = numRounds[keyLen/64 - 1];

#define F32(res,x,k32)  \
    {                                                           \
    DWORD t=x;                                                  \
    switch (k64Cnt & 3)                                         \
        {                                                       \
        case 0:  /* same as 4 */                                \
                    b0(t)   = p8(04)[b0(t)] ^ b0(k32[3]);       \
                    b1(t)   = p8(14)[b1(t)] ^ b1(k32[3]);       \
                    b2(t)   = p8(24)[b2(t)] ^ b2(k32[3]);       \
                    b3(t)   = p8(34)[b3(t)] ^ b3(k32[3]);       \
                 /* fall thru, having pre-processed t */        \
        case 3:     b0(t)   = p8(03)[b0(t)] ^ b0(k32[2]);       \
                    b1(t)   = p8(13)[b1(t)] ^ b1(k32[2]);       \
                    b2(t)   = p8(23)[b2(t)] ^ b2(k32[2]);       \
                    b3(t)   = p8(33)[b3(t)] ^ b3(k32[2]);       \
                 /* fall thru, having pre-processed t */        \
        case 2:  /* 128-bit keys (optimize for this case) */    \
            res=    MDStab[0][p8(01)[p8(02)[b0(t)] ^ b0(k32[1])] ^ b0(k32[0])] ^    \
                    MDStab[1][p8(11)[p8(12)[b1(t)] ^ b1(k32[1])] ^ b1(k32[0])] ^    \
                    MDStab[2][p8(21)[p8(22)[b2(t)] ^ b2(k32[1])] ^ b2(k32[0])] ^    \
                    MDStab[3][p8(31)[p8(32)[b3(t)] ^ b3(k32[1])] ^ b3(k32[0])] ;    \
        }                                                       \
    }


    subkeyCnt = ROUND_SUBKEYS + 2*rounds;
    k64Cnt=(keyLen+63)/64;          /* number of 64-bit key words */
    for (i=0,j=k64Cnt-1;i<k64Cnt;i++,j--)
        {                           /* split into even/odd key dwords */
        k32e[i]=key32[2*i  ];
        k32o[i]=key32[2*i+1];
        /* compute S-box keys using (12,8) Reed-Solomon code over GF(256) */
        sKey[j]=RS_MDS_Encode(k32e[i],k32o[i]);    /* reverse order */
        }

    for (i=q=0;i<subkeyCnt/2;i++,q+=SK_STEP)    
        {                           /* compute round subkeys for PHT */
        F32(A,q        ,k32e);      /* A uses even key dwords */
        F32(B,q+SK_BUMP,k32o);      /* B uses odd  key dwords */
        B = rotl(B,8);
        key->subKeys[2*i  ] = A+B;  /* combine with a PHT */
        B = A + 2*B;
        key->subKeys[2*i+1] = rotl(B,SK_ROTL);
        }

    switch (keyLen) /* case out key length for speed in generating S-boxes */
        {
        case 128:
            #define one128(N,J) sbSet(N,i,J,p8(N##1)[L0[i+J]]^k0)
            #define sb128(N) {                  \
                Xor256(L0,p8(N##2),b##N(sKey[1]));  \
                { register DWORD k0=b##N(sKey[0]);  \
                for (i=0;i<256;i+=2) { one128(N,0); one128(N,1); } } }
            sb128(0); sb128(1); sb128(2); sb128(3);
            break;
        case 192:
            #define one192(N,J) sbSet(N,i,J,p8(N##1)[p8(N##2)[L0[i+J]]^k1]^k0)
            #define sb192(N) {                      \
                Xor256(L0,p8(N##3),b##N(sKey[2]));  \
                { register DWORD k0=b##N(sKey[0]);  \
                  register DWORD k1=b##N(sKey[1]);  \
                  for (i=0;i<256;i+=2) { one192(N,0); one192(N,1); } } }
            sb192(0); sb192(1); sb192(2); sb192(3);
            break;
        case 256:
            #define one256(N,J) sbSet(N,i,J,p8(N##1)[p8(N##2)[L0[i+J]]^k1]^k0)
            #define sb256(N) {                                      \
                Xor256(L1,p8(N##4),b##N(sKey[3]));                  \
                for (i=0;i<256;i+=2) {L0[i  ]=p8(N##3)[L1[i]];      \
                                      L0[i+1]=p8(N##3)[L1[i+1]]; }  \
                Xor256(L0,L0,b##N(sKey[2]));                        \
                { register DWORD k0=b##N(sKey[0]);                  \
                  register DWORD k1=b##N(sKey[1]);                  \
                  for (i=0;i<256;i+=2) { one256(N,0); one256(N,1); } } }
            sb256(0); sb256(1); sb256(2); sb256(3);
            break;
        }

    /* Precompute the reversed round subkey order. */
    memcpy(key->subKeys2, key->subKeys, sizeof(key->subKeys2));
    r0=key->subKeys2+ROUND_SUBKEYS;
    r1=r0 + 2*rounds - 2;
    for (;r0 < r1;r0+=2,r1-=2)
        {
        t0=r0[0];           /* swap the order */
        t1=r0[1];
        r0[0]=r1[0];        /* but keep relative order within pairs */
        r0[1]=r1[1];
        r1[0]=t0;
        r1[1]=t1;
        }

    return TRUE;
    }


/*
+*****************************************************************************
*
* Function Name:    blockEncrypt
*
* Function:         Encrypt block(s) of data using Twofish
*
* Arguments:        cipher      =   ptr to already initialized cipherInstance
*                   key         =   ptr to already initialized keyInstance
*                   input       =   ptr to data blocks to be encrypted
*                   inputLen    =   # bits to encrypt (multiple of blockSize)
*                   outBuffer   =   ptr to where to put encrypted blocks
*
* Return:           # bits ciphered (>= 0)
*                   else error code (e.g., BAD_CIPHER_STATE, BAD_KEY_MATERIAL)
*
* Notes: The only supported block size for ECB/CBC modes is BLOCK_SIZE bits.
*        If inputLen is not a multiple of BLOCK_SIZE bits in those modes,
*        an error BAD_INPUT_LEN is returned.  In CFB1 mode, all block 
*        sizes can be supported.
*
-****************************************************************************/
static void twofishEncryptBlock(Key * pKey, octet * pabBlock)
    {
    KeyData * key = (KeyData *) pKey->pExpandedKey;
    DWORD x[BLOCK_SIZE/32];         /* block being encrypted */
    DWORD t0,t1;                    /* temp variables */

#define LoadBlockE(N)  x[N]=Bswap(((DWORD *)pabBlock)[N]) ^ key->subKeys2[INPUT_WHITEN+N]
        LoadBlockE(0);  LoadBlockE(1);  LoadBlockE(2);  LoadBlockE(3);
#define EncryptRound(K,R,id)    \
            t0     = Fe32##id(x[K  ],0);                    \
            t1     = Fe32##id(x[K^1],3);                    \
            x[K^3] = rotl(x[K^3],1);                         \
            x[K^2]^= t0 +   t1 + key->subKeys2[ROUND_SUBKEYS+2*(R)  ]; \
            x[K^3]^= t0 + 2*t1 + key->subKeys2[ROUND_SUBKEYS+2*(R)+1]; \
            x[K^2] = rotr(x[K^2],1);
#define     Encrypt2(R,id)  { EncryptRound(0,R+1,id); EncryptRound(2,R,id); }

        Encrypt2(14,_);
        Encrypt2(12,_);
        Encrypt2(10,_);
        Encrypt2( 8,_);
        Encrypt2( 6,_);
        Encrypt2( 4,_);
        Encrypt2( 2,_);
        Encrypt2( 0,_);

        /* need to do (or undo, depending on your point of view) final swap */
#if LittleEndian
#define StoreBlockE(N)  ((DWORD *)pabBlock)[N]=x[N^2] ^ key->subKeys2[OUTPUT_WHITEN+N]
#else
#define StoreBlockE(N)  { t0=x[N^2] ^ key->subKeys2[OUTPUT_WHITEN+N]; ((DWORD *)pabBlock)[N]=Bswap(t0); }
#endif
        StoreBlockE(0); StoreBlockE(1); StoreBlockE(2); StoreBlockE(3);

    }


/*
+*****************************************************************************
*
* Function Name:    blockDecrypt
*
* Function:         Decrypt block(s) of data using Twofish
*
* Arguments:        cipher      =   ptr to already initialized cipherInstance
*                   key         =   ptr to already initialized keyInstance
*                   input       =   ptr to data blocks to be decrypted
*                   inputLen    =   # bits to encrypt (multiple of blockSize)
*                   outBuffer   =   ptr to where to put decrypted blocks
*
* Return:           # bits ciphered (>= 0)
*                   else error code (e.g., BAD_CIPHER_STATE, BAD_KEY_MATERIAL)
*
* Notes: The only supported block size for ECB/CBC modes is BLOCK_SIZE bits.
*        If inputLen is not a multiple of BLOCK_SIZE bits in those modes,
*        an error BAD_INPUT_LEN is returned.  In CFB1 mode, all block 
*        sizes can be supported.
*
-****************************************************************************/
static void twofishDecryptBlock(Key * pKey, octet * pabBlock)
    {
    KeyData * key = (KeyData *) pKey->pExpandedKey;
    DWORD x[BLOCK_SIZE/32];         /* block being encrypted */
    DWORD t0,t1;                    /* temp variables */

#define LoadBlockD(N) x[N^2]=Bswap(((DWORD *)pabBlock)[N]) ^ key->subKeys[OUTPUT_WHITEN+N]
        LoadBlockD(0);  LoadBlockD(1);  LoadBlockD(2);  LoadBlockD(3);

#define DecryptRound(K,R,id)                                \
            t0     = Fe32##id(x[K  ],0);                    \
            t1     = Fe32##id(x[K^1],3);                    \
            x[K^2] = rotl (x[K^2],1);                        \
            x[K^2]^= t0 +   t1 + key->subKeys[ROUND_SUBKEYS+2*(R)  ]; \
            x[K^3]^= t0 + 2*t1 + key->subKeys[ROUND_SUBKEYS+2*(R)+1]; \
            x[K^3] = rotr (x[K^3],1);                        

#define     Decrypt2(R,id)  { DecryptRound(2,R+1,id); DecryptRound(0,R,id); }

        Decrypt2(14,_);
        Decrypt2(12,_);
        Decrypt2(10,_);
        Decrypt2( 8,_);
        Decrypt2( 6,_);
        Decrypt2( 4,_);
        Decrypt2( 2,_);
        Decrypt2( 0,_);

#if LittleEndian
#define StoreBlockD(N)  ((DWORD *)pabBlock)[N] = x[N] ^ key->subKeys[INPUT_WHITEN+N]
#else
#define StoreBlockD(N)  { t0=x[N]^key->subKeys[INPUT_WHITEN+N]; ((DWORD *)pabBlock)[N] = Bswap(t0); }
#endif
            StoreBlockD(0); StoreBlockD(1); StoreBlockD(2); StoreBlockD(3);

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

   reKey(key, pKey->cbKey * 8, (DWORD *) pKey->pabKey);

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

Cipher cipherTwofish2 =
{
   "twofish_ref",
   "Twofish block cipher (reference implementation)",
   aTwofishSizes,
   twofishExpandKey,
   twofishFreeExpandedKey,
   twofishEncryptBlock,
   twofishDecryptBlock
};
