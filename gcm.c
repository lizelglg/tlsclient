/******************************************************************************
*
* THIS SOURCE CODE IS HEREBY PLACED INTO THE PUBLIC DOMAIN FOR THE GOOD OF ALL
*
* This is a simple and straightforward implementation of the AES Rijndael
* 128-bit block cipher designed by Vincent Rijmen and Joan Daemen. The focus
* of this work was correctness & accuracy.  It is written in 'C' without any
* particular focus upon optimization or speed. It should be endian (memory
* byte order) neutral since the few places that care are handled explicitly.
*
* This implementation of Rijndael was created by Steven M. Gibson of GRC.com.
*
* It is intended for general purpose use, but was written in support of GRC's
* reference implementation of the SQRL (Secure Quick Reliable Login) client.
*
* See:    http://csrc.nist.gov/archive/aes/rijndael/wsdindex.html
*
* NO COPYRIGHT IS CLAIMED IN THIS WORK, HOWEVER, NEITHER IS ANY WARRANTY MADE
* REGARDING ITS FITNESS FOR ANY PARTICULAR PURPOSE. USE IT AT YOUR OWN RISK.
*
*******************************************************************************/
//#define AES_DECRYPTION	1

#define ENCRYPT         1       // specify whether we're encrypting
#define DECRYPT         0       // or decrypting
typedef unsigned char uchar;    // add some convienent shorter types
typedef unsigned int uint;
typedef struct {
    int mode;           // 1 for Encryption, 0 for Decryption
    int rounds;         // keysize-based rounds count
    uint32_t *rk;       // pointer to current round key
    uint32_t buf[68];   // key expansion buffer
} aes_context;


static int aes_tables_inited = 0;   // run-once flag for performing key
                                    // expasion table generation (see below)
/*
 *  The following static local tables must be filled-in before the first use of
 *  the GCM or AES ciphers. They are used for the AES key expansion/scheduling
 *  and once built are read-only and thread safe. The "gcm_initialize" function
 *  must be called once during system initialization to populate these arrays
 *  for subsequent use by the AES key scheduler. If they have not been built
 *  before attempted use, an error will be returned to the caller.
 *
 *  NOTE: GCM Encryption/Decryption does NOT REQUIRE AES decryption. Since
 *  GCM uses AES in counter-mode, where the AES cipher output is XORed with
 *  the GCM input, we ONLY NEED AES encryption.  Thus, to save space AES
 *  decryption is typically disabled by setting AES_DECRYPTION to 0 in aes.h.
 */
                            // We always need our forward tables
static uchar FSb[256];      // Forward substitution box (FSb)
static uint32_t FT0[256];   // Forward key schedule assembly tables
static uint32_t FT1[256];
static uint32_t FT2[256];
static uint32_t FT3[256];

#if AES_DECRYPTION          // We ONLY need reverse for decryption
static uchar RSb[256];      // Reverse substitution box (RSb)
static uint32_t RT0[256];   // Reverse key schedule assembly tables
static uint32_t RT1[256];
static uint32_t RT2[256];
static uint32_t RT3[256];
#endif                      /* AES_DECRYPTION */

static uint32_t RCON[10];   // AES round constants

/* 
 * Platform Endianness Neutralizing Load and Store Macro definitions
 * AES wants platform-neutral Little Endian (LE) byte ordering
 */
#define GET_UINT32_LE(n,b,i) {                  \
    (n) = ( (uint32_t) (b)[(i)    ]       )     \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )     \
        | ( (uint32_t) (b)[(i) + 2] << 16 )     \
        | ( (uint32_t) (b)[(i) + 3] << 24 ); }

#define PUT_UINT32_LE(n,b,i) {                  \
    (b)[(i)    ] = (uchar) ( (n)       );       \
    (b)[(i) + 1] = (uchar) ( (n) >>  8 );       \
    (b)[(i) + 2] = (uchar) ( (n) >> 16 );       \
    (b)[(i) + 3] = (uchar) ( (n) >> 24 ); }

/*
 *  AES forward and reverse encryption round processing macros
 */
#define AES_FROUND(rk, X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    X0 = (rk)[0] ^ FT0[ ( Y0       ) & 0xFF ] ^   \
                 FT1[ ( Y1 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y2 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y3 >> 24 ) & 0xFF ];    \
                                                \
    X1 = (rk)[1] ^ FT0[ ( Y1       ) & 0xFF ] ^   \
                 FT1[ ( Y2 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y3 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y0 >> 24 ) & 0xFF ];    \
                                                \
    X2 = (rk)[2] ^ FT0[ ( Y2       ) & 0xFF ] ^   \
                 FT1[ ( Y3 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y0 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y1 >> 24 ) & 0xFF ];    \
                                                \
    X3 = (rk)[3] ^ FT0[ ( Y3       ) & 0xFF ] ^   \
                 FT1[ ( Y0 >>  8 ) & 0xFF ] ^   \
                 FT2[ ( Y1 >> 16 ) & 0xFF ] ^   \
                 FT3[ ( Y2 >> 24 ) & 0xFF ];    \
}

#define AES_RROUND(rk, X0,X1,X2,X3,Y0,Y1,Y2,Y3)     \
{                                               \
    X0 = (rk)[0] ^ RT0[ ( Y0       ) & 0xFF ] ^   \
                 RT1[ ( Y3 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y2 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y1 >> 24 ) & 0xFF ];    \
                                                \
    X1 = (rk)[1] ^ RT0[ ( Y1       ) & 0xFF ] ^   \
                 RT1[ ( Y0 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y3 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y2 >> 24 ) & 0xFF ];    \
                                                \
    X2 = (rk)[2] ^ RT0[ ( Y2       ) & 0xFF ] ^   \
                 RT1[ ( Y1 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y0 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y3 >> 24 ) & 0xFF ];    \
                                                \
    X3 = (rk)[3] ^ RT0[ ( Y3       ) & 0xFF ] ^   \
                 RT1[ ( Y2 >>  8 ) & 0xFF ] ^   \
                 RT2[ ( Y1 >> 16 ) & 0xFF ] ^   \
                 RT3[ ( Y0 >> 24 ) & 0xFF ];    \
}

/*
 *  These macros improve the readability of the key
 *  generation initialization code by collapsing
 *  repetitive common operations into logical pieces.
 */
#define ROTL8(x) ( ( x << 8 ) & 0xFFFFFFFF ) | ( x >> 24 )
#define XTIME(x) ( ( x << 1 ) ^ ( ( x & 0x80 ) ? 0x1B : 0x00 ) )
#define MUL(x,y) ( ( x && y ) ? pow[(log[x]+log[y]) % 255] : 0 )
#define MIX(x,y) { y = ( (y << 1) | (y >> 7) ) & 0xFF; x ^= y; }
#define CPY128   { *RK++ = *SK++; *RK++ = *SK++; \
                   *RK++ = *SK++; *RK++ = *SK++; }

/******************************************************************************
 *
 *  AES_INIT_KEYGEN_TABLES
 *
 *  Fills the AES key expansion tables allocated above with their static
 *  data. This is not "per key" data, but static system-wide read-only
 *  table data. THIS FUNCTION IS NOT THREAD SAFE. It must be called once
 *  at system initialization to setup the tables for all subsequent use.
 *
 ******************************************************************************/
void aes_init_keygen_tables( void )
{
    int i, x, y, z;     // general purpose iteration and computation locals
    int pow[256];
    int log[256];

    if (aes_tables_inited) return;

    // fill the 'pow' and 'log' tables over GF(2^8)
    for( i = 0, x = 1; i < 256; i++ )   {
        pow[i] = x;
        log[x] = i;
        x = ( x ^ XTIME( x ) ) & 0xFF;
    }
    // compute the round constants
    for( i = 0, x = 1; i < 10; i++ )    {
        RCON[i] = (uint32_t) x;
        x = XTIME( x ) & 0xFF;
    }
    // fill the forward and reverse substitution boxes
    FSb[0x00] = 0x63;
#if AES_DECRYPTION  // whether AES decryption is supported
    RSb[0x63] = 0x00;
#endif /* AES_DECRYPTION */

    for( i = 1; i < 256; i++ )          {
        x = y = pow[255 - log[i]];
        MIX(x,y);
        MIX(x,y);
        MIX(x,y);
        MIX(x,y); 
        FSb[i] = (uchar) ( x ^= 0x63 );
#if AES_DECRYPTION  // whether AES decryption is supported
        RSb[x] = (uchar) i;
#endif /* AES_DECRYPTION */

    }
    // generate the forward and reverse key expansion tables
    for( i = 0; i < 256; i++ )          {
        x = FSb[i];
        y = XTIME( x ) & 0xFF;
        z =  ( y ^ x ) & 0xFF;

        FT0[i] = ( (uint32_t) y       ) ^ ( (uint32_t) x <<  8 ) ^
                 ( (uint32_t) x << 16 ) ^ ( (uint32_t) z << 24 );

        FT1[i] = ROTL8( FT0[i] );
        FT2[i] = ROTL8( FT1[i] );
        FT3[i] = ROTL8( FT2[i] );

#if AES_DECRYPTION  // whether AES decryption is supported
        x = RSb[i];

        RT0[i] = ( (uint32_t) MUL( 0x0E, x )       ) ^
                 ( (uint32_t) MUL( 0x09, x ) <<  8 ) ^
                 ( (uint32_t) MUL( 0x0D, x ) << 16 ) ^
                 ( (uint32_t) MUL( 0x0B, x ) << 24 );

        RT1[i] = ROTL8( RT0[i] );
        RT2[i] = ROTL8( RT1[i] );
        RT3[i] = ROTL8( RT2[i] );
#endif /* AES_DECRYPTION */
    }
    aes_tables_inited = 1;  // flag that the tables have been generated
}                           // to permit subsequent use of the AES cipher

/******************************************************************************
 *
 *  AES_SET_ENCRYPTION_KEY
 *
 *  This is called by 'aes_setkey' when we're establishing a key for
 *  subsequent encryption.  We give it a pointer to the encryption
 *  context, a pointer to the key, and the key's length in bytes.
 *  Valid lengths are: 16, 24 or 32 bytes (128, 192, 256 bits).
 *
 ******************************************************************************/
int aes_set_encryption_key( aes_context *ctx,
                            const uchar *key,
                            uint keysize )
{
    uint i;                 // general purpose iteration local
    uint32_t *RK = ctx->rk; // initialize our RoundKey buffer pointer

    for( i = 0; i < (keysize >> 2); i++ ) {
        GET_UINT32_LE( RK[i], key, i << 2 );
    }

    switch( ctx->rounds )
    {
        case 10:
            for( i = 0; i < 10; i++, RK += 4 ) {
				int v = RK[3];
                RK[4]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( v >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( v >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( v >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( v       ) & 0xFF ] << 24 );

                RK[5]  = RK[1] ^ RK[4];
                RK[6]  = RK[2] ^ RK[5];
                RK[7]  = RK[3] ^ RK[6];
            }
            break;

        case 12:
            for( i = 0; i < 8; i++, RK += 6 ) {
				int v = RK[5];
                RK[6]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( v >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( v >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( v >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( v       ) & 0xFF ] << 24 );

                RK[7]  = RK[1] ^ RK[6];
                RK[8]  = RK[2] ^ RK[7];
                RK[9]  = RK[3] ^ RK[8];
                RK[10] = RK[4] ^ RK[9];
                RK[11] = RK[5] ^ RK[10];
            }
            break;

        case 14:
            for( i = 0; i < 7; i++, RK += 8 ) {
				int v = RK[7];
                RK[8]  = RK[0] ^ RCON[i] ^
                ( (uint32_t) FSb[ ( v >>  8 ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( v >> 16 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( v >> 24 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( v       ) & 0xFF ] << 24 );

                RK[9]  = RK[1] ^ RK[8];
                RK[10] = RK[2] ^ RK[9];
                RK[11] = RK[3] ^ RK[10];
				
				 v = RK[11];
                RK[12] = RK[4] ^
                ( (uint32_t) FSb[ ( v       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( v >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( v >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( v >> 24 ) & 0xFF ] << 24 );

                RK[13] = RK[5] ^ RK[12];
                RK[14] = RK[6] ^ RK[13];
                RK[15] = RK[7] ^ RK[14];
            }
            break;

	default:
	    return -1;
    }
    return( 0 );
}

#if AES_DECRYPTION  // whether AES decryption is supported

/******************************************************************************
 *
 *  AES_SET_DECRYPTION_KEY
 *
 *  This is called by 'aes_setkey' when we're establishing a
 *  key for subsequent decryption.  We give it a pointer to
 *  the encryption context, a pointer to the key, and the key's
 *  length in bits. Valid lengths are: 128, 192, or 256 bits.
 *
 ******************************************************************************/
int aes_set_decryption_key( aes_context *ctx,
                            const uchar *key,
                            uint keysize )
{
    int i, j;
    aes_context cty;            // a calling aes context for set_encryption_key
    uint32_t *RK = ctx->rk;     // initialize our RoundKey buffer pointer
    uint32_t *SK;
    int ret;

    cty.rounds = ctx->rounds;   // initialize our local aes context
    cty.rk = cty.buf;           // round count and key buf pointer

    if (( ret = aes_set_encryption_key( &cty, key, keysize )) != 0 )
        return( ret );

    SK = cty.rk + cty.rounds * 4;

    CPY128  // copy a 128-bit block from *SK to *RK

    for( i = ctx->rounds - 1, SK -= 8; i > 0; i--, SK -= 8 ) {
        for( j = 0; j < 4; j++, SK++ ) {
            *RK++ = RT0[ FSb[ ( *SK       ) & 0xFF ] ] ^
                    RT1[ FSb[ ( *SK >>  8 ) & 0xFF ] ] ^
                    RT2[ FSb[ ( *SK >> 16 ) & 0xFF ] ] ^
                    RT3[ FSb[ ( *SK >> 24 ) & 0xFF ] ];
        }
    }
    CPY128  // copy a 128-bit block from *SK to *RK
    memset( &cty, 0, sizeof( aes_context ) );   // clear local aes context
    return( 0 );
}

#endif /* AES_DECRYPTION */

/******************************************************************************
 *
 *  AES_SETKEY
 *
 *  Invoked to establish the key schedule for subsequent encryption/decryption
 *
 ******************************************************************************/
int aes_setkey( aes_context *ctx,   // AES context provided by our caller
                int mode,           // ENCRYPT or DECRYPT flag
                const uchar *key,   // pointer to the key
                uint keysize )      // key length in bytes
{
    // since table initialization is not thread safe, we could either add
    // system-specific mutexes and init the AES key generation tables on
    // demand, or ask the developer to simply call "gcm_initialize" once during
    // application startup before threading begins. That's what we choose.
    if( !aes_tables_inited ) return ( -1 );  // fail the call when not inited.
    
    ctx->mode = mode;       // capture the key type we're creating
    ctx->rk = ctx->buf;     // initialize our round key pointer

    switch( keysize )       // set the rounds count based upon the keysize
    {
        case 16: ctx->rounds = 10; break;   // 16-byte, 128-bit key
        case 24: ctx->rounds = 12; break;   // 24-byte, 192-bit key
        case 32: ctx->rounds = 14; break;   // 32-byte, 256-bit key
	default: return(-1);
    }

#if AES_DECRYPTION
    if( mode == DECRYPT )   // expand our key for encryption or decryption
        return( aes_set_decryption_key( ctx, key, keysize ) );
    else     /* ENCRYPT */
#endif /* AES_DECRYPTION */
        return( aes_set_encryption_key( ctx, key, keysize ) );
}

/******************************************************************************
 *
 *  AES_CIPHER
 *
 *  Perform AES encryption and decryption.
 *  The AES context will have been setup with the encryption mode
 *  and all keying information appropriate for the task.
 *
 ******************************************************************************/
int aes_cipher( aes_context *ctx,
                    const uchar *input,
                    uchar *output )
{
    uint32_t X0, X1, X2, X3, Y0, Y1, Y2, Y3,*RK;   // general purpose locals
    int i;

    RK = ctx->rk;

    GET_UINT32_LE( X0, input,  0 ); X0 ^= RK[0];    // load our 128-bit
    GET_UINT32_LE( X1, input,  4 ); X1 ^= RK[1];    // input buffer in a storage
    GET_UINT32_LE( X2, input,  8 ); X2 ^= RK[2];    // memory endian-neutral way
    GET_UINT32_LE( X3, input, 12 ); X3 ^= RK[3];
	RK+=4;

#if AES_DECRYPTION  // whether AES decryption is supported

    if( ctx->mode == DECRYPT )
    {
        for( i = (ctx->rounds >> 1) - 1; i > 0; i-- )
        {
            AES_RROUND(RK, Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
            AES_RROUND(RK+4, X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
			RK+=8;
        }

        AES_RROUND(RK, Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

        X0 = RK[4] ^ \
                ( (uint32_t) RSb[ ( Y0       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

        X1 = RK[5] ^ \
                ( (uint32_t) RSb[ ( Y1       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );

        X2 = RK[6] ^ \
                ( (uint32_t) RSb[ ( Y2       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

        X3 = RK[7] ^ \
                ( (uint32_t) RSb[ ( Y3       ) & 0xFF ]       ) ^
                ( (uint32_t) RSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) RSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) RSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );
    }
    else /* ENCRYPT */
    {
#endif /* AES_DECRYPTION */

        for( i = (ctx->rounds >> 1) - 1; i > 0; i-- )
        {
            AES_FROUND(RK, Y0, Y1, Y2, Y3, X0, X1, X2, X3 );
            AES_FROUND(RK+4, X0, X1, X2, X3, Y0, Y1, Y2, Y3 );
			RK+=8;
        }

        AES_FROUND(RK, Y0, Y1, Y2, Y3, X0, X1, X2, X3 );

        X0 = RK[4] ^ \
                ( (uint32_t) FSb[ ( Y0       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y1 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y2 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y3 >> 24 ) & 0xFF ] << 24 );

        X1 = RK[5] ^ \
                ( (uint32_t) FSb[ ( Y1       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y2 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y3 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y0 >> 24 ) & 0xFF ] << 24 );

        X2 = RK[6] ^ \
                ( (uint32_t) FSb[ ( Y2       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y3 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y0 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y1 >> 24 ) & 0xFF ] << 24 );

        X3 = RK[7] ^ \
                ( (uint32_t) FSb[ ( Y3       ) & 0xFF ]       ) ^
                ( (uint32_t) FSb[ ( Y0 >>  8 ) & 0xFF ] <<  8 ) ^
                ( (uint32_t) FSb[ ( Y1 >> 16 ) & 0xFF ] << 16 ) ^
                ( (uint32_t) FSb[ ( Y2 >> 24 ) & 0xFF ] << 24 );
    PUT_UINT32_LE( X0, output,  0 );
    PUT_UINT32_LE( X1, output,  4 );
    PUT_UINT32_LE( X2, output,  8 );
    PUT_UINT32_LE( X3, output, 12 );

#if AES_DECRYPTION  // whether AES decryption is supported
    }
#endif /* AES_DECRYPTION */


    return( 0 );
}
/* end of aes.c */
































/******************************************************************************
*
* THIS SOURCE CODE IS HEREBY PLACED INTO THE PUBLIC DOMAIN FOR THE GOOD OF ALL
*
* This is a simple and straightforward implementation of AES-GCM authenticated
* encryption. The focus of this work was correctness & accuracy. It is written
* in straight 'C' without any particular focus upon optimization or speed. It
* should be endian (memory byte order) neutral since the few places that care
* are handled explicitly.
*
* This implementation of AES-GCM was created by Steven M. Gibson of GRC.com.
*
* It is intended for general purpose use, but was written in support of GRC's
* reference implementation of the SQRL (Secure Quick Reliable Login) client.
*
* See:    http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
*         http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/
*         gcm/gcm-revised-spec.pdf
*
* NO COPYRIGHT IS CLAIMED IN THIS WORK, HOWEVER, NEITHER IS ANY WARRANTY MADE
* REGARDING ITS FITNESS FOR ANY PARTICULAR PURPOSE. USE IT AT YOUR OWN RISK.
*
*******************************************************************************/
#define GCM_AUTH_FAILURE    0x55555555  // authentication failure
typedef struct {
    int mode;               // cipher direction: encrypt/decrypt
    uint64_t len;           // cipher data length processed so far
    uint64_t add_len;       // total add data length
    uint64_t HL[16];        // precalculated lo-half HTable
    uint64_t HH[16];        // precalculated hi-half HTable
    uchar base_ectr[16];    // first counter-mode cipher output for tag
    uchar y[16];            // the current cipher-input IV|Counter value
    uchar buf[16];          // buf working value
    aes_context aes_ctx;    // cipher context used

	uchar table[16][256][16];

} gcm_context;

/******************************************************************************
 *                      ==== IMPLEMENTATION WARNING ====
 *
 *  This code was developed for use within SQRL's fixed environmnent. Thus, it
 *  is somewhat less "general purpose" than it would be if it were designed as
 *  a general purpose AES-GCM library. Specifically, it bothers with almost NO
 *  error checking on parameter limits, buffer bounds, etc. It assumes that it
 *  is being invoked by its author or by someone who understands the values it
 *  expects to receive. Its behavior will be undefined otherwise.
 *
 *  All functions that might fail are defined to return 'ints' to indicate a
 *  problem. Most do not do so now. But this allows for error propagation out
 *  of internal functions if robust error checking should ever be desired.
 *
 ******************************************************************************/

/* Calculating the "GHASH"
 *
 * There are many ways of calculating the so-called GHASH in software, each with
 * a traditional size vs performance tradeoff.  The GHASH (Galois field hash) is
 * an intriguing construction which takes two 128-bit strings (also the cipher's
 * block size and the fundamental operation size for the system) and hashes them
 * into a third 128-bit result.
 *
 * Many implementation solutions have been worked out that use large precomputed
 * table lookups in place of more time consuming bit fiddling, and this approach
 * can be scaled easily upward or downward as needed to change the time/space
 * tradeoff. It's been studied extensively and there's a solid body of theory and
 * practice.  For example, without using any lookup tables an implementation
 * might obtain 119 cycles per byte throughput, whereas using a simple, though
 * large, key-specific 64 kbyte 8-bit lookup table the performance jumps to 13
 * cycles per byte.
 *
 * And Intel's processors have, since 2010, included an instruction which does
 * the entire 128x128->128 bit job in just several 64x64->128 bit pieces.
 *
 * Since SQRL is interactive, and only processing a few 128-bit blocks, I've
 * settled upon a relatively slower but appealing small-table compromise which
 * folds a bunch of not only time consuming but also bit twiddling into a simple
 * 16-entry table which is attributed to Victor Shoup's 1996 work while at
 * Bellcore: "On Fast and Provably Secure MessageAuthentication Based on
 * Universal Hashing."  See: http://www.shoup.net/papers/macs.pdf
 * See, also section 4.1 of the "gcm-revised-spec" cited above.
 */

/*
 *  This 16-entry table of pre-computed constants is used by the
 *  GHASH multiplier to improve over a strictly table-free but
 *  significantly slower 128x128 bit multiple within GF(2^128).
 */
static const uint64_t last4[16] = {
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0  };

/*
 * Platform Endianness Neutralizing Load and Store Macro definitions
 * GCM wants platform-neutral Big Endian (BE) byte ordering
 */
#define GET_UINT32_BE(n,b,i) {                      \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )         \
        | ( (uint32_t) (b)[(i) + 1] << 16 )         \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )         \
        | ( (uint32_t) (b)[(i) + 3]       ); }

#define PUT_UINT32_BE(n,b,i) {                      \
    (b)[(i)    ] = (uchar) ( (n) >> 24 );   \
    (b)[(i) + 1] = (uchar) ( (n) >> 16 );   \
    (b)[(i) + 2] = (uchar) ( (n) >>  8 );   \
    (b)[(i) + 3] = (uchar) ( (n)       ); }


/******************************************************************************
 *
 *  GCM_INITIALIZE
 *
 *  Must be called once to initialize the GCM library.
 *
 *  At present, this only calls the AES keygen table generator, which expands
 *  the AES keying tables for use. This is NOT A THREAD-SAFE function, so it
 *  MUST be called during system initialization before a multi-threading
 *  environment is running.
 *
 ******************************************************************************/
int gcm_initialize( void )
{
    aes_init_keygen_tables();
    return( 0 );
}


/******************************************************************************
 *
 *  GCM_MULT
 *
 *  Performs a GHASH operation on the 128-bit input vector 'x', setting
 *  the 128-bit output vector to 'x' times H using our precomputed tables.
 *  'x' and 'output' are seen as elements of GCM's GF(2^128) Galois field.
 *
 ******************************************************************************/
static void gcm_mult( gcm_context *ctx,     // pointer to established context
                      const uchar x[16],    // pointer to 128-bit input vector
                      uchar output[16] )    // pointer to 128-bit output vector
{
    int i;
    uchar lo, hi, rem;
    uint64_t zh = 0, zl = 0;

    for( i = 15; i >= 0; i-- ) {
        lo = (uchar) ( x[i] & 0x0f );
        hi = (uchar) ( x[i] >> 4 );
		

        rem = (uchar) ( zl & 0x0f );
        zl = ( zh << 60 ) | ( zl >> 4 );
        zh = ( zh >> 4 );
        zl ^= ctx->HL[lo];
        zh ^= (last4[rem]<<48)^ctx->HH[lo];

        rem = (uchar) ( zl & 0x0f );
        zl = ( zh << 60 ) | ( zl >> 4 );
        zh = ( zh >> 4 );
        zl ^= ctx->HL[hi];
        zh ^= (last4[rem]<<48)^ctx->HH[hi];
    }
    PUT_UINT32_BE( zh >> 32, output, 0 );
    PUT_UINT32_BE( zh, output, 4 );
    PUT_UINT32_BE( zl >> 32, output, 8 );
    PUT_UINT32_BE( zl, output, 12 );
}
static void gcm_mult_h( gcm_context *ctx, const uchar I[16], uchar output[16] )    // pointer to 128-bit output vector
{
	unsigned char T[16];
	memcpy(T, &ctx->table[0][I[0]][0], 16);
	for (int x = 1; x < 16; x++) 
	   for (int y = 0; y < 16; y += sizeof(unsigned long))
		   *((unsigned long *)(T + y)) ^= *((unsigned long *)(&ctx->table[x][I[x]][y]));
	memcpy(output, T, 16);
}


/******************************************************************************
 *
 *  GCM_SETKEY
 *
 *  This is called to set the AES-GCM key. It initializes the AES key
 *  and populates the gcm context's pre-calculated HTables.
 *
 ******************************************************************************/

int gcm_setkey( gcm_context *ctx,   // pointer to caller-provided gcm context
                const uchar *key,   // pointer to the AES encryption key
                const uint keysize) // size in bytes (must be 16, 24, 32 for
		                    // 128, 192 or 256-bit keys respectively)
{
    int ret, i, j;
    uint64_t hi, lo;
    uint64_t vl, vh;
    unsigned char h[16];

    memset( ctx, 0, sizeof(gcm_context) );  // zero caller-provided GCM context
    memset( h, 0, 16 );                     // initialize the block to encrypt

    // encrypt the null 128-bit block to generate a key-based value
    // which is then used to initialize our GHASH lookup tables
    if(( ret = aes_setkey( &ctx->aes_ctx, ENCRYPT, key, keysize )) != 0 )
        return( ret );
    if(( ret = aes_cipher( &ctx->aes_ctx, h, h )) != 0 )
        return( ret );

    GET_UINT32_BE( hi, h,  0  );    // pack h as two 64-bit ints, big-endian
    GET_UINT32_BE( lo, h,  4  );
    vh = (uint64_t) hi << 32 | lo;

    GET_UINT32_BE( hi, h,  8  );
    GET_UINT32_BE( lo, h,  12 );
    vl = (uint64_t) hi << 32 | lo;

    ctx->HL[8] = vl;                // 8 = 1000 corresponds to 1 in GF(2^128)
    ctx->HH[8] = vh;
    ctx->HH[0] = 0;                 // 0 corresponds to 0 in GF(2^128)
    ctx->HL[0] = 0;

    for( i = 4; i > 0; i >>= 1 ) {
        uint32_t T = (uint32_t) ( vl & 1 ) * 0xe1000000U;
        vl  = ( vh << 63 ) | ( vl >> 1 );
        vh  = ( vh >> 1 ) ^ ( (uint64_t) T << 32);
        ctx->HL[i] = vl;
        ctx->HH[i] = vh;
    }
    for (i = 2; i < 16; i <<= 1 ) {
        uint64_t *HiL = ctx->HL + i, *HiH = ctx->HH + i;
        vh = *HiH;
        vl = *HiL;
        for( j = 1; j < i; j++ ) {
            HiH[j] = vh ^ ctx->HH[j];
            HiL[j] = vl ^ ctx->HL[j];
        }
    }
	
	unsigned char b[16];
	memset(b, 0, 16);
	for (int y = 0; y < 256; y++) {
	     b[0] = y;
	     gcm_mult(ctx, b, &ctx->table[0][y][0]);
	}
	
	static unsigned char gcm_shifttable[256*2] = {
	0x00, 0x00, 0x01, 0xc2, 0x03, 0x84, 0x02, 0x46, 0x07, 0x08, 0x06, 0xca, 0x04, 0x8c, 0x05, 0x4e,
	0x0e, 0x10, 0x0f, 0xd2, 0x0d, 0x94, 0x0c, 0x56, 0x09, 0x18, 0x08, 0xda, 0x0a, 0x9c, 0x0b, 0x5e,
	0x1c, 0x20, 0x1d, 0xe2, 0x1f, 0xa4, 0x1e, 0x66, 0x1b, 0x28, 0x1a, 0xea, 0x18, 0xac, 0x19, 0x6e,
	0x12, 0x30, 0x13, 0xf2, 0x11, 0xb4, 0x10, 0x76, 0x15, 0x38, 0x14, 0xfa, 0x16, 0xbc, 0x17, 0x7e,
	0x38, 0x40, 0x39, 0x82, 0x3b, 0xc4, 0x3a, 0x06, 0x3f, 0x48, 0x3e, 0x8a, 0x3c, 0xcc, 0x3d, 0x0e,
	0x36, 0x50, 0x37, 0x92, 0x35, 0xd4, 0x34, 0x16, 0x31, 0x58, 0x30, 0x9a, 0x32, 0xdc, 0x33, 0x1e,
	0x24, 0x60, 0x25, 0xa2, 0x27, 0xe4, 0x26, 0x26, 0x23, 0x68, 0x22, 0xaa, 0x20, 0xec, 0x21, 0x2e,
	0x2a, 0x70, 0x2b, 0xb2, 0x29, 0xf4, 0x28, 0x36, 0x2d, 0x78, 0x2c, 0xba, 0x2e, 0xfc, 0x2f, 0x3e,
	0x70, 0x80, 0x71, 0x42, 0x73, 0x04, 0x72, 0xc6, 0x77, 0x88, 0x76, 0x4a, 0x74, 0x0c, 0x75, 0xce,
	0x7e, 0x90, 0x7f, 0x52, 0x7d, 0x14, 0x7c, 0xd6, 0x79, 0x98, 0x78, 0x5a, 0x7a, 0x1c, 0x7b, 0xde,
	0x6c, 0xa0, 0x6d, 0x62, 0x6f, 0x24, 0x6e, 0xe6, 0x6b, 0xa8, 0x6a, 0x6a, 0x68, 0x2c, 0x69, 0xee,
	0x62, 0xb0, 0x63, 0x72, 0x61, 0x34, 0x60, 0xf6, 0x65, 0xb8, 0x64, 0x7a, 0x66, 0x3c, 0x67, 0xfe,
	0x48, 0xc0, 0x49, 0x02, 0x4b, 0x44, 0x4a, 0x86, 0x4f, 0xc8, 0x4e, 0x0a, 0x4c, 0x4c, 0x4d, 0x8e,
	0x46, 0xd0, 0x47, 0x12, 0x45, 0x54, 0x44, 0x96, 0x41, 0xd8, 0x40, 0x1a, 0x42, 0x5c, 0x43, 0x9e,
	0x54, 0xe0, 0x55, 0x22, 0x57, 0x64, 0x56, 0xa6, 0x53, 0xe8, 0x52, 0x2a, 0x50, 0x6c, 0x51, 0xae,
	0x5a, 0xf0, 0x5b, 0x32, 0x59, 0x74, 0x58, 0xb6, 0x5d, 0xf8, 0x5c, 0x3a, 0x5e, 0x7c, 0x5f, 0xbe,
	0xe1, 0x00, 0xe0, 0xc2, 0xe2, 0x84, 0xe3, 0x46, 0xe6, 0x08, 0xe7, 0xca, 0xe5, 0x8c, 0xe4, 0x4e,
	0xef, 0x10, 0xee, 0xd2, 0xec, 0x94, 0xed, 0x56, 0xe8, 0x18, 0xe9, 0xda, 0xeb, 0x9c, 0xea, 0x5e,
	0xfd, 0x20, 0xfc, 0xe2, 0xfe, 0xa4, 0xff, 0x66, 0xfa, 0x28, 0xfb, 0xea, 0xf9, 0xac, 0xf8, 0x6e,
	0xf3, 0x30, 0xf2, 0xf2, 0xf0, 0xb4, 0xf1, 0x76, 0xf4, 0x38, 0xf5, 0xfa, 0xf7, 0xbc, 0xf6, 0x7e,
	0xd9, 0x40, 0xd8, 0x82, 0xda, 0xc4, 0xdb, 0x06, 0xde, 0x48, 0xdf, 0x8a, 0xdd, 0xcc, 0xdc, 0x0e,
	0xd7, 0x50, 0xd6, 0x92, 0xd4, 0xd4, 0xd5, 0x16, 0xd0, 0x58, 0xd1, 0x9a, 0xd3, 0xdc, 0xd2, 0x1e,
	0xc5, 0x60, 0xc4, 0xa2, 0xc6, 0xe4, 0xc7, 0x26, 0xc2, 0x68, 0xc3, 0xaa, 0xc1, 0xec, 0xc0, 0x2e,
	0xcb, 0x70, 0xca, 0xb2, 0xc8, 0xf4, 0xc9, 0x36, 0xcc, 0x78, 0xcd, 0xba, 0xcf, 0xfc, 0xce, 0x3e,
	0x91, 0x80, 0x90, 0x42, 0x92, 0x04, 0x93, 0xc6, 0x96, 0x88, 0x97, 0x4a, 0x95, 0x0c, 0x94, 0xce,
	0x9f, 0x90, 0x9e, 0x52, 0x9c, 0x14, 0x9d, 0xd6, 0x98, 0x98, 0x99, 0x5a, 0x9b, 0x1c, 0x9a, 0xde,
	0x8d, 0xa0, 0x8c, 0x62, 0x8e, 0x24, 0x8f, 0xe6, 0x8a, 0xa8, 0x8b, 0x6a, 0x89, 0x2c, 0x88, 0xee,
	0x83, 0xb0, 0x82, 0x72, 0x80, 0x34, 0x81, 0xf6, 0x84, 0xb8, 0x85, 0x7a, 0x87, 0x3c, 0x86, 0xfe,
	0xa9, 0xc0, 0xa8, 0x02, 0xaa, 0x44, 0xab, 0x86, 0xae, 0xc8, 0xaf, 0x0a, 0xad, 0x4c, 0xac, 0x8e,
	0xa7, 0xd0, 0xa6, 0x12, 0xa4, 0x54, 0xa5, 0x96, 0xa0, 0xd8, 0xa1, 0x1a, 0xa3, 0x5c, 0xa2, 0x9e,
	0xb5, 0xe0, 0xb4, 0x22, 0xb6, 0x64, 0xb7, 0xa6, 0xb2, 0xe8, 0xb3, 0x2a, 0xb1, 0x6c, 0xb0, 0xae,
	0xbb, 0xf0, 0xba, 0x32, 0xb8, 0x74, 0xb9, 0xb6, 0xbc, 0xf8, 0xbd, 0x3a, 0xbf, 0x7c, 0xbe, 0xbe };
	/* now generate the rest of the tables based the previous table */
	for (int x = 1; x < 16; x++) {
	   for (int y = 0; y < 256; y++) {
	      /* now shift it right by 8 bits */
	      uchar t = ctx->table[x-1][y][15];
	      for (int z = 15; z > 0; z--)
	          ctx->table[x][y][z] = ctx->table[x-1][y][z-1];

	      ctx->table[x][y][0] = gcm_shifttable[t<<1];
	      ctx->table[x][y][1] ^= gcm_shifttable[(t<<1)+1];
	   }
	 }
	
	return( 0 );
}


/******************************************************************************
 *
 *    GCM processing occurs four phases: SETKEY, START, UPDATE and FINISH.
 *
 *  SETKEY: 
 *  
 *   START: Sets the Encryption/Decryption mode.
 *          Accepts the initialization vector and additional data.
 *
 *  UPDATE: Encrypts or decrypts the plaintext or ciphertext.
 *
 *  FINISH: Performs a final GHASH to generate the authentication tag.
 *
 ******************************************************************************
 *
 *  GCM_START
 *
 *  Given a user-provided GCM context, this initializes it, sets the encryption
 *  mode, and preprocesses the initialization vector and additional AEAD data.
 *
 ******************************************************************************/
int gcm_start( gcm_context *ctx,    // pointer to user-provided GCM context
               int mode,            // GCM_ENCRYPT or GCM_DECRYPT
               const uchar *iv,     // pointer to initialization vector
               size_t iv_len,       // IV length in bytes (should == 12)
               const uchar *add,    // ptr to additional AEAD data (NULL if none)
               size_t add_len )     // length of additional AEAD data (bytes)
{
    int ret;            // our error return if the AES encrypt fails
    uchar work_buf[16]; // XOR source built from provided IV if len != 16
    const uchar *p;     // general purpose array pointer
    size_t use_len;     // byte count to process, up to 16 bytes
    size_t i;           // local loop iterator

    // since the context might be reused under the same key
    // we zero the working buffers for this next new process
    memset( ctx->y,   0x00, sizeof(ctx->y  ) );
    memset( ctx->buf, 0x00, sizeof(ctx->buf) );
    ctx->len = 0;
    ctx->add_len = 0;

    ctx->mode = mode;               // set the GCM encryption/decryption mode
    ctx->aes_ctx.mode = ENCRYPT;    // GCM *always* runs AES in ENCRYPTION mode

    if( iv_len == 12 ) {                // GCM natively uses a 12-byte, 96-bit IV
        memcpy( ctx->y, iv, iv_len );   // copy the IV to the top of the 'y' buff
        ctx->y[15] = 1;                 // start "counting" from 1 (not 0)
    }
    else    // if we don't have a 12-byte IV, we GHASH whatever we've been given
    {   
        memset( work_buf, 0x00, 16 );               // clear the working buffer
        PUT_UINT32_BE( iv_len * 8, work_buf, 12 );  // place the IV into buffer

        p = iv;
        while( iv_len > 0 ) {
            use_len = ( iv_len < 16 ) ? iv_len : 16;
            for( i = 0; i < use_len; i++ ) ctx->y[i] ^= p[i];
				gcm_mult_h( ctx, ctx->y, ctx->y );
            iv_len -= use_len;
            p += use_len;
        }
        for( i = 0; i < 16; i++ ) ctx->y[i] ^= work_buf[i];
			gcm_mult_h( ctx, ctx->y, ctx->y );
    }
    if( ( ret = aes_cipher( &ctx->aes_ctx, ctx->y, ctx->base_ectr ) ) != 0 )
        return( ret );

    ctx->add_len = add_len;
    p = add;
    while( add_len > 0 ) {
        use_len = ( add_len < 16 ) ? add_len : 16;
        for( i = 0; i < use_len; i++ ) ctx->buf[i] ^= p[i];
			gcm_mult_h( ctx, ctx->buf, ctx->buf );
        add_len -= use_len;
        p += use_len;
    }
    return( 0 );
}

/******************************************************************************
 *
 *  GCM_UPDATE
 *
 *  This is called once or more to process bulk plaintext or ciphertext data.
 *  We give this some number of bytes of input and it returns the same number
 *  of output bytes. If called multiple times (which is fine) all but the final
 *  invocation MUST be called with length mod 16 == 0. (Only the final call can
 *  have a partial block length of < 128 bits.)
 *
 ******************************************************************************/
int gcm_update( gcm_context *ctx,       // pointer to user-provided GCM context
                size_t length,          // length, in bytes, of data to process
                const uchar *input,     // pointer to source data
                uchar *output )         // pointer to destination data
{
    int ret;            // our error return if the AES encrypt fails
    uchar ectr[16];     // counter-mode cipher output for XORing
    size_t use_len;     // byte count to process, up to 16 bytes
    size_t i;           // local loop iterator

    ctx->len += length; // bump the GCM context's running length count

    while( length > 0 ) {
        // clamp the length to process at 16 bytes
        use_len = ( length < 16 ) ? length : 16;

        // increment the context's 128-bit IV||Counter 'y' vector
        for( i = 16; i > 12; i-- ) if( ++ctx->y[i - 1] != 0 ) break;

        // encrypt the context's 'y' vector under the established key
        if( ( ret = aes_cipher( &ctx->aes_ctx, ctx->y, ectr ) ) != 0 )
            return( ret );

        // encrypt or decrypt the input to the output
        if( ctx->mode == ENCRYPT )  
        {
             for( i = 0; i+sizeof(int) <= use_len; i+=sizeof(int) ) {
                *(int*)&output[i] =  *(int*)&ectr[i] ^ *(int*)&input[i];
                *(int*)&ctx->buf[i] ^= *(int*)&output[i];
            }
             for(; i < use_len; i++ ) {
                output[i] = (uchar) ( ectr[i] ^ input[i] );
                ctx->buf[i] ^= output[i];
            }
        }
		else                        
        {
             for( i = 0; i+sizeof(int) <= use_len; i+=sizeof(int) ) {
       	        *(int*)&ctx->buf[i] ^= *(int*)&input[i];
                *(int*)&output[i] = *(int*)&ectr[i] ^ *(int*)&input[i] ;
             }
            for( i ; i < use_len; i++ ) {
       	        ctx->buf[i] ^= input[i];
                output[i] = (uchar) ( ectr[i] ^ input[i] );
             }
        }
		
		gcm_mult_h(ctx, ctx->buf, ctx->buf);

        length -= use_len;  // drop the remaining byte count to process
        input  += use_len;  // bump our input pointer forward
        output += use_len;  // bump our output pointer forward
    }
    return( 0 );
}

/******************************************************************************
 *
 *  GCM_FINISH
 *
 *  This is called once after all calls to GCM_UPDATE to finalize the GCM.
 *  It performs the final GHASH to produce the resulting authentication TAG.
 *
 ******************************************************************************/
int gcm_finish( gcm_context *ctx,   // pointer to user-provided GCM context
                uchar *tag,         // pointer to buffer which receives the tag
                size_t tag_len )    // length, in bytes, of the tag-receiving buf
{
    uchar work_buf[16];
    uint64_t orig_len     = ctx->len * 8;
    uint64_t orig_add_len = ctx->add_len * 8;
    size_t i;

    if( tag_len != 0 ) memcpy( tag, ctx->base_ectr, tag_len );

    if( orig_len || orig_add_len ) {
        memset( work_buf, 0x00, 16 );

        PUT_UINT32_BE( ( orig_add_len >> 32 ), work_buf, 0  );
        PUT_UINT32_BE( ( orig_add_len       ), work_buf, 4  );
        PUT_UINT32_BE( ( orig_len     >> 32 ), work_buf, 8  );
        PUT_UINT32_BE( ( orig_len           ), work_buf, 12 );

        for( i = 0; i < 16; i++ ) ctx->buf[i] ^= work_buf[i];
        gcm_mult_h( ctx, ctx->buf, ctx->buf );
        for( i = 0; i < tag_len; i++ ) tag[i] ^= ctx->buf[i];
    }
    return( 0 );
}


/******************************************************************************
 *
 *  GCM_CRYPT_AND_TAG
 *
 *  This either encrypts or decrypts the user-provided data and, either
 *  way, generates an authentication tag of the requested length. It must be
 *  called with a GCM context whose key has already been set with GCM_SETKEY.
 *
 *  The user would typically call this explicitly to ENCRYPT a buffer of data
 *  and optional associated data, and produce its an authentication tag.
 *
 *  To reverse the process the user would typically call the companion
 *  GCM_AUTH_DECRYPT function to decrypt data and verify a user-provided
 *  authentication tag.  The GCM_AUTH_DECRYPT function calls this function
 *  to perform its decryption and tag generation, which it then compares.
 *
 ******************************************************************************/
int gcm_crypt_and_tag(
        gcm_context *ctx,       // gcm context with key already setup
        int mode,               // cipher direction: GCM_ENCRYPT or GCM_DECRYPT
        const uchar *iv,        // pointer to the 12-byte initialization vector
        size_t iv_len,          // byte length if the IV. should always be 12
        const uchar *add,       // pointer to the non-ciphered additional data
        size_t add_len,         // byte length of the additional AEAD data
        const uchar *input,     // pointer to the cipher data source
        uchar *output,          // pointer to the cipher data destination
        size_t length,          // byte length of the cipher data
        uchar *tag,             // pointer to the tag to be generated
        size_t tag_len )        // byte length of the tag to be generated
{   /*
       assuming that the caller has already invoked gcm_setkey to
       prepare the gcm context with the keying material, we simply
       invoke each of the three GCM sub-functions in turn...
    */
    gcm_start  ( ctx, mode, iv, iv_len, add, add_len );
    gcm_update ( ctx, length, input, output );
    gcm_finish ( ctx, tag, tag_len );
    return( 0 );
}


/******************************************************************************
 *
 *  GCM_AUTH_DECRYPT
 *
 *  This DECRYPTS a user-provided data buffer with optional associated data.
 *  It then verifies a user-supplied authentication tag against the tag just
 *  re-created during decryption to verify that the data has not been altered.
 *
 *  This function calls GCM_CRYPT_AND_TAG (above) to perform the decryption
 *  and authentication tag generation.
 *
 ******************************************************************************/
int gcm_auth_decrypt(
        gcm_context *ctx,       // gcm context with key already setup
        const uchar *iv,        // pointer to the 12-byte initialization vector
        size_t iv_len,          // byte length if the IV. should always be 12
        const uchar *add,       // pointer to the non-ciphered additional data
        size_t add_len,         // byte length of the additional AEAD data
        const uchar *input,     // pointer to the cipher data source
        uchar *output,          // pointer to the cipher data destination
        size_t length,          // byte length of the cipher data
        const uchar *tag,       // pointer to the tag to be authenticated
        size_t tag_len )        // byte length of the tag <= 16
{
    uchar check_tag[16];        // the tag generated and returned by decryption
    int diff;                   // an ORed flag to detect authentication errors
    size_t i;                   // our local iterator
    /*
       we use GCM_DECRYPT_AND_TAG (above) to perform our decryption
       (which is an identical XORing to reverse the previous one)
       and also to re-generate the matching authentication tag
    */
    gcm_crypt_and_tag(  ctx, DECRYPT, iv, iv_len, add, add_len,
                        input, output, length, check_tag, tag_len );

    // now we verify the authentication tag in 'constant time'
    for( diff = 0, i = 0; i < tag_len; i++ )
        diff |= tag[i] ^ check_tag[i];

    if( diff != 0 ) {                   // see whether any bits differed?
        memset( output, 0, length );    // if so... wipe the output data
        return( GCM_AUTH_FAILURE );     // return GCM_AUTH_FAILURE
    }
    return( 0 );
}

/******************************************************************************
 *
 *  GCM_ZERO_CTX
 *
 *  The GCM context contains both the GCM context and the AES context.
 *  This includes keying and key-related material which is security-
 *  sensitive, so it MUST be zeroed after use. This function does that.
 *
 ******************************************************************************/
void gcm_zero_ctx( gcm_context *ctx )
{
    // zero the context originally provided to us
    memset( ctx, 0, sizeof( gcm_context ) );
}
