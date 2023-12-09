
#define TLS_CHACHA20_IV_LENGTH    12

// ChaCha20 implementation by D. J. Bernstein
// Public domain.

#define CHACHA_MINKEYLEN    16
#define CHACHA_NONCELEN     8
#define CHACHA_NONCELEN_96  12
#define CHACHA_CTRLEN       8
#define CHACHA_CTRLEN_96    4
#define CHACHA_STATELEN     (CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN     64

#define POLY1305_MAX_AAD    32
#define POLY1305_KEYLEN     32
#define POLY1305_TAGLEN     16

#define u_int   unsigned int
#define uint8_t unsigned char
#define u_char  unsigned char
#ifndef NULL
#define NULL (void *)0
#endif

#if (CRYPT >= 0x0117) && (0)
    // to do: use ltc chacha/poly1305 implementation (working on big-endian machines)
    #define chacha_ctx                                  chacha20poly1305_state
    #define poly1305_context                            poly1305_state

    #define _private_tls_poly1305_init(ctx, key, len)  poly1305_init(ctx, key, len)
    #define _private_tls_poly1305_update(ctx, in, len) poly1305_process(ctx, in, len)
    #define _private_tls_poly1305_finish(ctx, mac)     poly1305_done(ctx, mac, 16)
#else
struct chacha_ctx {
    u_int input[16];
    uint8_t ks[CHACHA_BLOCKLEN];
    uint8_t unused;
};

static  void chacha_keysetup(struct chacha_ctx *x, const u_char *k, u_int kbits);
static  void chacha_ivsetup(struct chacha_ctx *x, const u_char *iv, const u_char *ctr);
static  void chacha_ivsetup_96bitnonce(struct chacha_ctx *x, const u_char *iv, const u_char *ctr);
static  void chacha_encrypt_bytes(struct chacha_ctx *x, const u_char *m, u_char *c, u_int bytes);
static  int poly1305_generate_key(unsigned char *key256, unsigned char *nonce, unsigned int noncelen, unsigned char *poly_key, unsigned int counter);

#define poly1305_block_size 16
#define poly1305_context poly1305_state_internal_t

//========== ChaCha20 from D. J. Bernstein ========= //
// Source available at https://cr.yp.to/chacha.html  //

typedef unsigned char u8;
typedef unsigned int u32;

typedef struct chacha_ctx chacha_ctx;

#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((u8)(v) & U8C(0xFF))
#define U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define _private_tls_U8TO32_LITTLE(p) \
  (((u32)((p)[0])) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))

#define _private_tls_U32TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } while (0)

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

static const char sigma[] = "expand 32-byte k";
static const char tau[] = "expand 16-byte k";

static  void chacha_keysetup(chacha_ctx *x, const u8 *k, u32 kbits) {
    const char *constants;

    x->input[4] = _private_tls_U8TO32_LITTLE(k + 0);
    x->input[5] = _private_tls_U8TO32_LITTLE(k + 4);
    x->input[6] = _private_tls_U8TO32_LITTLE(k + 8);
    x->input[7] = _private_tls_U8TO32_LITTLE(k + 12);
    if (kbits == 256) { /* recommended */
        k += 16;
        constants = sigma;
    } else { /* kbits == 128 */
        constants = tau;
    }
    x->input[8] = _private_tls_U8TO32_LITTLE(k + 0);
    x->input[9] = _private_tls_U8TO32_LITTLE(k + 4);
    x->input[10] = _private_tls_U8TO32_LITTLE(k + 8);
    x->input[11] = _private_tls_U8TO32_LITTLE(k + 12);
    x->input[0] = _private_tls_U8TO32_LITTLE(constants + 0);
    x->input[1] = _private_tls_U8TO32_LITTLE(constants + 4);
    x->input[2] = _private_tls_U8TO32_LITTLE(constants + 8);
    x->input[3] = _private_tls_U8TO32_LITTLE(constants + 12);
}

static  void chacha_key(chacha_ctx *x, u8 *k) {
    _private_tls_U32TO8_LITTLE(k, x->input[4]);
    _private_tls_U32TO8_LITTLE(k + 4, x->input[5]);
    _private_tls_U32TO8_LITTLE(k + 8, x->input[6]);
    _private_tls_U32TO8_LITTLE(k + 12, x->input[7]);

    _private_tls_U32TO8_LITTLE(k + 16, x->input[8]);
    _private_tls_U32TO8_LITTLE(k + 20, x->input[9]);
    _private_tls_U32TO8_LITTLE(k + 24, x->input[10]);
    _private_tls_U32TO8_LITTLE(k + 28, x->input[11]);
}

static  void chacha_nonce(chacha_ctx *x, u8 *nonce) {
    _private_tls_U32TO8_LITTLE(nonce + 0, x->input[13]);
    _private_tls_U32TO8_LITTLE(nonce + 4, x->input[14]);
    _private_tls_U32TO8_LITTLE(nonce + 8, x->input[15]);
}

static  void chacha_ivsetup(chacha_ctx *x, const u8 *iv, const u8 *counter) {
    x->input[12] = counter == NULL ? 0 : _private_tls_U8TO32_LITTLE(counter + 0);
    x->input[13] = counter == NULL ? 0 : _private_tls_U8TO32_LITTLE(counter + 4);
    if (iv) {
        x->input[14] = _private_tls_U8TO32_LITTLE(iv + 0);
        x->input[15] = _private_tls_U8TO32_LITTLE(iv + 4);
    }
}

static  void chacha_ivsetup_96bitnonce(chacha_ctx *x, const u8 *iv, const u8 *counter) {
    x->input[12] = counter == NULL ? 0 : _private_tls_U8TO32_LITTLE(counter + 0);
    if (iv) {
        x->input[13] = _private_tls_U8TO32_LITTLE(iv + 0);
        x->input[14] = _private_tls_U8TO32_LITTLE(iv + 4);
        x->input[15] = _private_tls_U8TO32_LITTLE(iv + 8);
    }
}

static  void chacha_ivupdate(chacha_ctx *x, const u8 *iv, const u8 *aad, const u8 *counter) {
    x->input[12] = counter == NULL ? 0 : _private_tls_U8TO32_LITTLE(counter + 0);
    x->input[13] = _private_tls_U8TO32_LITTLE(iv + 0);
    x->input[14] = _private_tls_U8TO32_LITTLE(iv + 4) ^ _private_tls_U8TO32_LITTLE(aad);
    x->input[15] = _private_tls_U8TO32_LITTLE(iv + 8) ^ _private_tls_U8TO32_LITTLE(aad + 4);
}

static  void chacha_encrypt_bytes(chacha_ctx *x, const u8 *m, u8 *c, u32 bytes) {
    u32 x0, x1, x2, x3, x4, x5, x6, x7;
    u32 x8, x9, x10, x11, x12, x13, x14, x15;
    u32 j0, j1, j2, j3, j4, j5, j6, j7;
    u32 j8, j9, j10, j11, j12, j13, j14, j15;
    u8 *ctarget = NULL;
    u8 tmp[64];
    u_int i;

    if (!bytes)
        return;

    j0 = x->input[0];
    j1 = x->input[1];
    j2 = x->input[2];
    j3 = x->input[3];
    j4 = x->input[4];
    j5 = x->input[5];
    j6 = x->input[6];
    j7 = x->input[7];
    j8 = x->input[8];
    j9 = x->input[9];
    j10 = x->input[10];
    j11 = x->input[11];
    j12 = x->input[12];
    j13 = x->input[13];
    j14 = x->input[14];
    j15 = x->input[15];

    for (;;) {
        if (bytes < 64) {
            for (i = 0; i < bytes; ++i)
                tmp[i] = m[i];
            m = tmp;
            ctarget = c;
            c = tmp;
        }
        x0 = j0;
        x1 = j1;
        x2 = j2;
        x3 = j3;
        x4 = j4;
        x5 = j5;
        x6 = j6;
        x7 = j7;
        x8 = j8;
        x9 = j9;
        x10 = j10;
        x11 = j11;
        x12 = j12;
        x13 = j13;
        x14 = j14;
        x15 = j15;
        for (i = 20; i > 0; i -= 2) {
            QUARTERROUND(x0, x4, x8, x12)
            QUARTERROUND(x1, x5, x9, x13)
            QUARTERROUND(x2, x6, x10, x14)
            QUARTERROUND(x3, x7, x11, x15)
            QUARTERROUND(x0, x5, x10, x15)
            QUARTERROUND(x1, x6, x11, x12)
            QUARTERROUND(x2, x7, x8, x13)
            QUARTERROUND(x3, x4, x9, x14)
        }
        x0 = PLUS(x0, j0);
        x1 = PLUS(x1, j1);
        x2 = PLUS(x2, j2);
        x3 = PLUS(x3, j3);
        x4 = PLUS(x4, j4);
        x5 = PLUS(x5, j5);
        x6 = PLUS(x6, j6);
        x7 = PLUS(x7, j7);
        x8 = PLUS(x8, j8);
        x9 = PLUS(x9, j9);
        x10 = PLUS(x10, j10);
        x11 = PLUS(x11, j11);
        x12 = PLUS(x12, j12);
        x13 = PLUS(x13, j13);
        x14 = PLUS(x14, j14);
        x15 = PLUS(x15, j15);

        if (bytes < 64) {
            _private_tls_U32TO8_LITTLE(x->ks + 0, x0);
            _private_tls_U32TO8_LITTLE(x->ks + 4, x1);
            _private_tls_U32TO8_LITTLE(x->ks + 8, x2);
            _private_tls_U32TO8_LITTLE(x->ks + 12, x3);
            _private_tls_U32TO8_LITTLE(x->ks + 16, x4);
            _private_tls_U32TO8_LITTLE(x->ks + 20, x5);
            _private_tls_U32TO8_LITTLE(x->ks + 24, x6);
            _private_tls_U32TO8_LITTLE(x->ks + 28, x7);
            _private_tls_U32TO8_LITTLE(x->ks + 32, x8);
            _private_tls_U32TO8_LITTLE(x->ks + 36, x9);
            _private_tls_U32TO8_LITTLE(x->ks + 40, x10);
            _private_tls_U32TO8_LITTLE(x->ks + 44, x11);
            _private_tls_U32TO8_LITTLE(x->ks + 48, x12);
            _private_tls_U32TO8_LITTLE(x->ks + 52, x13);
            _private_tls_U32TO8_LITTLE(x->ks + 56, x14);
            _private_tls_U32TO8_LITTLE(x->ks + 60, x15);
        }

        x0 = XOR(x0, _private_tls_U8TO32_LITTLE(m + 0));
        x1 = XOR(x1, _private_tls_U8TO32_LITTLE(m + 4));
        x2 = XOR(x2, _private_tls_U8TO32_LITTLE(m + 8));
        x3 = XOR(x3, _private_tls_U8TO32_LITTLE(m + 12));
        x4 = XOR(x4, _private_tls_U8TO32_LITTLE(m + 16));
        x5 = XOR(x5, _private_tls_U8TO32_LITTLE(m + 20));
        x6 = XOR(x6, _private_tls_U8TO32_LITTLE(m + 24));
        x7 = XOR(x7, _private_tls_U8TO32_LITTLE(m + 28));
        x8 = XOR(x8, _private_tls_U8TO32_LITTLE(m + 32));
        x9 = XOR(x9, _private_tls_U8TO32_LITTLE(m + 36));
        x10 = XOR(x10, _private_tls_U8TO32_LITTLE(m + 40));
        x11 = XOR(x11, _private_tls_U8TO32_LITTLE(m + 44));
        x12 = XOR(x12, _private_tls_U8TO32_LITTLE(m + 48));
        x13 = XOR(x13, _private_tls_U8TO32_LITTLE(m + 52));
        x14 = XOR(x14, _private_tls_U8TO32_LITTLE(m + 56));
        x15 = XOR(x15, _private_tls_U8TO32_LITTLE(m + 60));

        j12 = PLUSONE(j12);
        if (!j12) {
            j13 = PLUSONE(j13);
            /*
             * Stopping at 2^70 bytes per nonce is the user's
             * responsibility.
             */
        }

        _private_tls_U32TO8_LITTLE(c + 0, x0);
        _private_tls_U32TO8_LITTLE(c + 4, x1);
        _private_tls_U32TO8_LITTLE(c + 8, x2);
        _private_tls_U32TO8_LITTLE(c + 12, x3);
        _private_tls_U32TO8_LITTLE(c + 16, x4);
        _private_tls_U32TO8_LITTLE(c + 20, x5);
        _private_tls_U32TO8_LITTLE(c + 24, x6);
        _private_tls_U32TO8_LITTLE(c + 28, x7);
        _private_tls_U32TO8_LITTLE(c + 32, x8);
        _private_tls_U32TO8_LITTLE(c + 36, x9);
        _private_tls_U32TO8_LITTLE(c + 40, x10);
        _private_tls_U32TO8_LITTLE(c + 44, x11);
        _private_tls_U32TO8_LITTLE(c + 48, x12);
        _private_tls_U32TO8_LITTLE(c + 52, x13);
        _private_tls_U32TO8_LITTLE(c + 56, x14);
        _private_tls_U32TO8_LITTLE(c + 60, x15);

        if (bytes <= 64) {
            if (bytes < 64) {
                for (i = 0; i < bytes; ++i)
                    ctarget[i] = c[i];
            }
            x->input[12] = j12;
            x->input[13] = j13;
            x->unused = 64 - bytes;
            return;
        }
        bytes -= 64;
        c += 64;
        m += 64;
    }
}

static  void chacha20_block(chacha_ctx *x, unsigned char *c, u_int len) {
    u_int i;

    unsigned int state[16];
    for (i = 0; i < 16; i++)
        state[i] = x->input[i];
    for (i = 20; i > 0; i -= 2) {
        QUARTERROUND(state[0], state[4], state[8], state[12])
        QUARTERROUND(state[1], state[5], state[9], state[13])
        QUARTERROUND(state[2], state[6], state[10], state[14])
        QUARTERROUND(state[3], state[7], state[11], state[15])
        QUARTERROUND(state[0], state[5], state[10], state[15])
        QUARTERROUND(state[1], state[6], state[11], state[12])
        QUARTERROUND(state[2], state[7], state[8], state[13])
        QUARTERROUND(state[3], state[4], state[9], state[14])
    }

    for (i = 0; i < 16; i++)
        x->input[i] = PLUS(x->input[i], state[i]);

    for (i = 0; i < len; i += 4) {
        _private_tls_U32TO8_LITTLE(c + i, x->input[i/4]);
    }
}

static  int poly1305_generate_key(unsigned char *key256, unsigned char *nonce, unsigned int noncelen, unsigned char *poly_key, unsigned int counter) {
    struct chacha_ctx ctx;
    uint64_t ctr;
    memset(&ctx, 0, sizeof(ctx));
    chacha_keysetup(&ctx, key256, 256);
    switch (noncelen) {
        case 8:
            ctr = counter;
            chacha_ivsetup(&ctx, nonce, (unsigned char *)&ctr);
            break;
        case 12:
            chacha_ivsetup_96bitnonce(&ctx, nonce, (unsigned char *)&counter);
            break;
        default:
            return -1;
    }
    chacha20_block(&ctx, poly_key, POLY1305_KEYLEN);
    return 0;
}

/* 17 + sizeof(size_t) + 14*sizeof(unsigned long) */
typedef struct poly1305_state_internal_t {
    unsigned long r[5];
    unsigned long h[5];
    unsigned long pad[4];
    size_t leftover;
    unsigned char buffer[poly1305_block_size];
    unsigned char final;
} poly1305_state_internal_t;

/* interpret four 8 bit unsigned integers as a 32 bit unsigned integer in little endian */
static unsigned long _private_tls_U8TO32(const unsigned char *p) {
    return
        (((unsigned long)(p[0] & 0xff)      ) |
         ((unsigned long)(p[1] & 0xff) <<  8) |
         ((unsigned long)(p[2] & 0xff) << 16) |
         ((unsigned long)(p[3] & 0xff) << 24));
}

/* store a 32 bit unsigned integer as four 8 bit unsigned integers in little endian */
static void _private_tls_U32TO8(unsigned char *p, unsigned long v) {
    p[0] = (v      ) & 0xff;
    p[1] = (v >>  8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

void _private_tls_poly1305_init(poly1305_context *ctx, const unsigned char key[32]) {
    poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;

    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    st->r[0] = (_private_tls_U8TO32(&key[ 0])     ) & 0x3ffffff;
    st->r[1] = (_private_tls_U8TO32(&key[ 3]) >> 2) & 0x3ffff03;
    st->r[2] = (_private_tls_U8TO32(&key[ 6]) >> 4) & 0x3ffc0ff;
    st->r[3] = (_private_tls_U8TO32(&key[ 9]) >> 6) & 0x3f03fff;
    st->r[4] = (_private_tls_U8TO32(&key[12]) >> 8) & 0x00fffff;

    /* h = 0 */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;

    /* save pad for later */
    st->pad[0] = _private_tls_U8TO32(&key[16]);
    st->pad[1] = _private_tls_U8TO32(&key[20]);
    st->pad[2] = _private_tls_U8TO32(&key[24]);
    st->pad[3] = _private_tls_U8TO32(&key[28]);

    st->leftover = 0;
    st->final = 0;
}

static void _private_tls_poly1305_blocks(poly1305_state_internal_t *st, const unsigned char *m, size_t bytes) {
    const unsigned long hibit = (st->final) ? 0 : (1UL << 24); /* 1 << 128 */
    unsigned long r0,r1,r2,r3,r4;
    unsigned long s1,s2,s3,s4;
    unsigned long h0,h1,h2,h3,h4;
    unsigned long long d0,d1,d2,d3,d4;
    unsigned long c;

    r0 = st->r[0];
    r1 = st->r[1];
    r2 = st->r[2];
    r3 = st->r[3];
    r4 = st->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

    while (bytes >= poly1305_block_size) {
        /* h += m[i] */
        h0 += (_private_tls_U8TO32(m+ 0)     ) & 0x3ffffff;
        h1 += (_private_tls_U8TO32(m+ 3) >> 2) & 0x3ffffff;
        h2 += (_private_tls_U8TO32(m+ 6) >> 4) & 0x3ffffff;
        h3 += (_private_tls_U8TO32(m+ 9) >> 6) & 0x3ffffff;
        h4 += (_private_tls_U8TO32(m+12) >> 8) | hibit;

        /* h *= r */
        d0 = ((unsigned long long)h0 * r0) + ((unsigned long long)h1 * s4) + ((unsigned long long)h2 * s3) + ((unsigned long long)h3 * s2) + ((unsigned long long)h4 * s1);
        d1 = ((unsigned long long)h0 * r1) + ((unsigned long long)h1 * r0) + ((unsigned long long)h2 * s4) + ((unsigned long long)h3 * s3) + ((unsigned long long)h4 * s2);
        d2 = ((unsigned long long)h0 * r2) + ((unsigned long long)h1 * r1) + ((unsigned long long)h2 * r0) + ((unsigned long long)h3 * s4) + ((unsigned long long)h4 * s3);
        d3 = ((unsigned long long)h0 * r3) + ((unsigned long long)h1 * r2) + ((unsigned long long)h2 * r1) + ((unsigned long long)h3 * r0) + ((unsigned long long)h4 * s4);
        d4 = ((unsigned long long)h0 * r4) + ((unsigned long long)h1 * r3) + ((unsigned long long)h2 * r2) + ((unsigned long long)h3 * r1) + ((unsigned long long)h4 * r0);

        /* (partial) h %= p */
                      c = (unsigned long)(d0 >> 26); h0 = (unsigned long)d0 & 0x3ffffff;
        d1 += c;      c = (unsigned long)(d1 >> 26); h1 = (unsigned long)d1 & 0x3ffffff;
        d2 += c;      c = (unsigned long)(d2 >> 26); h2 = (unsigned long)d2 & 0x3ffffff;
        d3 += c;      c = (unsigned long)(d3 >> 26); h3 = (unsigned long)d3 & 0x3ffffff;
        d4 += c;      c = (unsigned long)(d4 >> 26); h4 = (unsigned long)d4 & 0x3ffffff;
        h0 += c * 5;  c =                (h0 >> 26); h0 =                h0 & 0x3ffffff;
        h1 += c;

        m += poly1305_block_size;
        bytes -= poly1305_block_size;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
    st->h[3] = h3;
    st->h[4] = h4;
}

void _private_tls_poly1305_finish(poly1305_context *ctx, unsigned char mac[16]) {
    poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
    unsigned long h0,h1,h2,h3,h4,c;
    unsigned long g0,g1,g2,g3,g4;
    unsigned long long f;
    unsigned long mask;

    /* process the remaining block */
    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        for (; i < poly1305_block_size; i++)
            st->buffer[i] = 0;
        st->final = 1;
        _private_tls_poly1305_blocks(st, st->buffer, poly1305_block_size);
    }

    /* fully carry h */
    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

                 c = h1 >> 26; h1 = h1 & 0x3ffffff;
    h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
    h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
    h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
    h1 +=     c;

    /* compute h + -p */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1UL << 26);

    /* select h if h < p, or h + -p if h >= p */
    mask = (g4 >> ((sizeof(unsigned long) * 8) - 1)) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

    /* mac = (h + pad) % (2^128) */
    f = (unsigned long long)h0 + st->pad[0]            ; h0 = (unsigned long)f;
    f = (unsigned long long)h1 + st->pad[1] + (f >> 32); h1 = (unsigned long)f;
    f = (unsigned long long)h2 + st->pad[2] + (f >> 32); h2 = (unsigned long)f;
    f = (unsigned long long)h3 + st->pad[3] + (f >> 32); h3 = (unsigned long)f;

    _private_tls_U32TO8(mac +  0, h0);
    _private_tls_U32TO8(mac +  4, h1);
    _private_tls_U32TO8(mac +  8, h2);
    _private_tls_U32TO8(mac + 12, h3);

    /* zero out the state */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;
    st->r[0] = 0;
    st->r[1] = 0;
    st->r[2] = 0;
    st->r[3] = 0;
    st->r[4] = 0;
    st->pad[0] = 0;
    st->pad[1] = 0;
    st->pad[2] = 0;
    st->pad[3] = 0;
}

void _private_tls_poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes) {
    poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
    size_t i;
    /* handle leftover */
    if (st->leftover) {
        size_t want = (poly1305_block_size - st->leftover);
        if (want > bytes)
            want = bytes;
        for (i = 0; i < want; i++)
            st->buffer[st->leftover + i] = m[i];
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < poly1305_block_size)
            return;
        _private_tls_poly1305_blocks(st, st->buffer, poly1305_block_size);
        st->leftover = 0;
    }

    /* process full blocks */
    if (bytes >= poly1305_block_size) {
        size_t want = (bytes & ~(poly1305_block_size - 1));
        _private_tls_poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }

    /* store leftover */
    if (bytes) {
        for (i = 0; i < bytes; i++)
            st->buffer[st->leftover + i] = m[i];
        st->leftover += bytes;
    }
}

int poly1305_verify(const unsigned char mac1[16], const unsigned char mac2[16]) {
    size_t i;
    unsigned int dif = 0;
    for (i = 0; i < 16; i++)
        dif |= (mac1[i] ^ mac2[i]);
    dif = (dif - 1) >> ((sizeof(unsigned int) * 8) - 1);
    return (dif & 1);
}

void chacha20_poly1305_key(struct chacha_ctx *ctx, unsigned char *poly1305_key) {
    unsigned char key[32];
    unsigned char nonce[12];
    chacha_key(ctx, key);
    chacha_nonce(ctx, nonce);
    poly1305_generate_key(key, nonce, sizeof(nonce), poly1305_key, 0);
}

int chacha20_poly1305_aead(struct chacha_ctx *ctx,  unsigned char *pt, unsigned int len, unsigned char *aad, unsigned int aad_len, unsigned char *poly_key, unsigned char *out) {
    static unsigned char zeropad[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    if (aad_len > POLY1305_MAX_AAD)
        return -1;

    unsigned int counter = 1;
    chacha_ivsetup_96bitnonce(ctx, NULL, (unsigned char *)&counter);
    chacha_encrypt_bytes(ctx, pt, out, len);
    
    poly1305_context aead_ctx;
    _private_tls_poly1305_init(&aead_ctx, poly_key);
    _private_tls_poly1305_update(&aead_ctx, aad, aad_len);
    int rem = aad_len % 16;
    if (rem)
        _private_tls_poly1305_update(&aead_ctx, zeropad, 16 - rem);
    _private_tls_poly1305_update(&aead_ctx, out, len);
    rem = len % 16;
    if (rem)
        _private_tls_poly1305_update(&aead_ctx, zeropad, 16 - rem);

    unsigned char trail[16];
    _private_tls_U32TO8(trail, aad_len);
    *(int *)(trail + 4) = 0;
    _private_tls_U32TO8(trail + 8, len);
    *(int *)(trail + 12) = 0;

    _private_tls_poly1305_update(&aead_ctx, trail, 16);
    _private_tls_poly1305_finish(&aead_ctx, out + len);
    
    return len + POLY1305_TAGLEN;
}
int chacha20_poly1305_decode(struct chacha_ctx *remote_ctx,  unsigned char *pt, unsigned int len, unsigned char *aad, unsigned int aad_len, unsigned char *poly_key, unsigned char *out)
{
	len -= POLY1305_TAGLEN;

	chacha_encrypt_bytes(remote_ctx, pt, out, len);
	
	chacha20_poly1305_key(remote_ctx, poly_key);
	poly1305_context ctx;
	_private_tls_poly1305_init(&ctx, poly_key);
	_private_tls_poly1305_update(&ctx, aad, aad_len);
	static unsigned char zeropad[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	int rem = aad_len % 16;
	if (rem)
	    _private_tls_poly1305_update(&ctx, zeropad, 16 - rem);
	_private_tls_poly1305_update(&ctx, pt, len);
	rem = len % 16;
	if (rem)
	    _private_tls_poly1305_update(&ctx, zeropad, 16 - rem);
	
    unsigned char trail[16];
	_private_tls_U32TO8(&trail[0], aad_len == 5 ? 5 : 13);
	*(int *)&trail[4] = 0;
	_private_tls_U32TO8(&trail[8], len);
	*(int *)&trail[12] = 0;
	
	unsigned char mac_tag[POLY1305_TAGLEN];
	_private_tls_poly1305_update(&ctx, trail, 16);
	_private_tls_poly1305_finish(&ctx, mac_tag);
	if (memcmp(mac_tag, pt + len, POLY1305_TAGLEN))
		return -1;
	return len;
}
#endif