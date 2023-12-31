#pragma once

typedef unsigned char uchar;
typedef unsigned int uint;

//Implement secure re-negotiation per RFC5746.


#define ISCLIENT    1
#define ISSERVER    0


#define SSL_VERSION_MAJOR   3
#define SSL_VERSION_MINOR   1
#define SSL_VERSION_MINOR1  1
#define SSL_VERSION_MINOR3  3


// The following defines SSL 3.0 content types
#define CONTENT_CHANGECIPHERSPEC    0x14
#define CONTENT_ALERT               0x15
#define CONTENT_HANDSHAKE           0x16
#define CONTENT_APPLICATION_DATA    0x17


//The following defines SSL 3.0/TLS 1.0 Handshake message types
#define MSG_HELLO_REQUEST           0x00
#define MSG_CLIENT_HELLO            0x01
#define MSG_SERVER_HELLO            0x02
#define MSG_NEW_SESSION_TICKET      0x04
#define MSG_END_OF_EARLY_DATA       0x05  // RFC8446
#define MSG_ENCRYPTED_EXTENSIONS    0x08  // RFC8446
#define MSG_CERTIFICATE             0x0B
#define MSG_SERVER_KEY_EXCHANGE     0x0C  // Used in TLS1.2 but not in TLS1.3
#define MSG_CERTIFICATE_REQUEST     0x0D
#define MSG_SERVER_HELLO_DONE       0x0E  // Not used in TLS1.3
#define MSG_CERTIFICATE_VERIFY      0x0F
#define MSG_CLIENT_KEY_EXCHANGE     0x10  // Not used in TLS1.3
#define MSG_FINISHED                0x14
#define MSG_KEY_UPDATE              0x18  // RFC8446
#define MSG_MESSAGE_HASH            0xFE  // RFC8446

//The followings are used for secured re-negotiation. See RFC5746.
#define MSG_EXTENTION               0xFF
#define MSG_EXTENTION_RENEGOTIATION 0x01

//This is only used in CONTENT_CHANGECIPHERSPEC content type
#define MSG_CHANGE_CIPHER_SPEC      0x01


//The following defines SSL 3.0/TLS 1.0 ALERT message types
//1st byte of ALERT message indicates whether it is a warning or fatal.
#define ALERT_WARNING               0x01
#define ALERT_FATAL                 0x02
//2nd byte of ALERT message indicates the nature of the alert.
#define ALERT_NOTIFY_CLOSE          0x00
#define ALERT_MESSAGE_UNEXPECTED    0x0A
#define ALERT_RECORD_MAC_BAD        0x14
#define ALERT_DECRYPTION_FAILED     0x15
#define ALERT_RECORD_OVERFLOW       0x16
#define ALERT_DECOMPRESSION_FAILED  0x1E
#define ALERT_HANDSHAKE_FAILED      0x28
#define ALERT_CERTIFICATE_BAD       0x2A
#define ALERT_CERTIFICATE_UNSUPPORTED   0x2B
#define ALERT_CERTIFICATE_REVOKED   0x2C
#define ALERT_CERTIFICATE_EXPIRED   0x2D
#define ALERT_CERTIFICATE_UNKNOWN   0x2E
#define ALERT_PARAMETER_ILLEGAL     0x2F
#define ALERT_CA_UNKNOWN            0x30
#define ALERT_ACCESS_DENIED         0x31
#define ALERT_DECODE_ERROR          0x32
#define ALERT_DECRYPT_ERROR         0x33
#define ALERT_EXPORT_RESTRICTION    0x3C
#define ALERT_PROTOCOL_VERSION      0x46
#define ALERT_SECURITY_INSUFFICIENT 0x47
#define ALERT_INTERNAL_ERROR        0x50
#define ALERT_USER_CANCELED         0x5A
#define ALERT_NO_NEGOTIATION        0x64
#define ALERT_UNSUPPORTED_EXTENSION 0x6E // RFC8446


#define PAD1_BYTE                   0x36
#define PAD2_BYTE                   0x5C
#define PADSIZE_MD5                 0x30
#define PADSIZE_SHA                 0x28
#define MD5_SIZE                    16
#define SHA1_SIZE                   20

//Do not change these values. They are defined by SSL 3.0.
#define RANDOM_SIZE             32
#define TLS_SECRET_LEN          32  // Length of TLS1.3 secret
#define SSL_SECRET_LEN          48  // Length of TLS1.2 secret

#define MAC_SECRET_LEN          16
#define WRITE_KEY_LEN           16

#define CHALLENGE_LEN           16  //Challenge length of V.20 ClientHello
#define TLS_VERIFY_LEN          12  //Verify block length for TLS 1.0 and later.

typedef struct CTX {
    uint    data[54];  // Was 28
} CTX;

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-3
typedef enum {
    TLS_NONE = 0x0000,                  // 0x00, 0x00   Y[RFC5246]
    TLS_RSA_WITH_NULL_MD5,              // 0x00, 0x01   Y[RFC5246]
    TLS_RSA_WITH_NULL_SHA,              // 0x00, 0x02   Y[RFC5246]
    TLS_RSA_EXPORT_WITH_RC4_40_MD5,     // 0x00, 0x03   N[RFC4346][RFC6347]
    TLS_RSA_WITH_RC4_128_MD5,           // 0x00, 0x04   N[RFC5246][RFC6347]
    TLS_RSA_WITH_RC4_128_SHA,           // 0x00, 0x05   N[RFC5246][RFC6347]
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5, // 0x00, 0x06   Y[RFC4346]
    TLS_RSA_WITH_IDEA_CBC_SHA,          // 0x00, 0x07   Y[RFC5469]
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,  // 0x00, 0x08   Y[RFC4346]
    TLS_RSA_WITH_DES_CBC_SHA,           // 0x00, 0x09   Y[RFC5469]
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,      // 0x00, 0x0A   Y[RFC5246]
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA, //0x00,0x0B   Y[RFC4346]
    TLS_DH_DSS_WITH_DES_CBC_SHA,        // 0x00, 0x0C   Y[RFC5469]
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,   // 0x00, 0x0D   Y[RFC5246]
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA, //0x00,0x0E   Y[RFC4346]
    TLS_DH_RSA_WITH_DES_CBC_SHA,        // 0x00, 0x0F   Y[RFC5469]
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,   // 0x00, 0x10   Y[RFC5246]
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,//0x00,0x11   Y[RFC4346]
    TLS_DHE_DSS_WITH_DES_CBC_SHA,       // 0x00, 0x12   Y[RFC5469]
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,  // 0x00, 0x13   Y[RFC5246]
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,//0x00,0x14   Y[RFC4346]
    TLS_DHE_RSA_WITH_DES_CBC_SHA,       // 0x00, 0x15   Y[RFC5469]
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,  // 0x00, 0x16   Y[RFC5246]
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5, // 0x00, 0x17   N[RFC4346][RFC6347]
    TLS_DH_anon_WITH_RC4_128_MD5,       // 0x00, 0x18   N[RFC5246][RFC6347]
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,//0x00,0x19   Y[RFC4346]
    TLS_DH_anon_WITH_DES_CBC_SHA,       // 0x00, 0x1A   Y[RFC5469]
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,  // 0x00, 0x1B   Y[RFC5246]
    TLS_RESERVED_001C,                  // 0x00, 0x1C   Reserved to avoid conflicts with SSLv3[RFC5246]
    TLS_RESERVED_001D,                  // 0x00, 0x1D   Reserved to avoid conflicts with SSLv3[RFC5246]
    TLS_KRB5_WITH_DES_CBC_SHA,          // 0x00, 0x1E   Y[RFC2712]
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA,     // 0x00, 0x1F   Y[RFC2712]
    TLS_KRB5_WITH_RC4_128_SHA,          // 0x00, 0x20   N[RFC2712][RFC6347]
    TLS_KRB5_WITH_IDEA_CBC_SHA,         // 0x00, 0x21   Y[RFC2712]
    TLS_KRB5_WITH_DES_CBC_MD5,          // 0x00, 0x22   Y[RFC2712]
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5,     // 0x00, 0x23   Y[RFC2712]
    TLS_KRB5_WITH_RC4_128_MD5,          // 0x00, 0x24   N[RFC2712][RFC6347]
    TLS_KRB5_WITH_IDEA_CBC_MD5,         // 0x00, 0x25   Y[RFC2712]
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA, //0x00, 0x26   Y[RFC2712]
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA, //0x00, 0x27   Y[RFC2712]
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA,    // 0x00, 0x28   N[RFC2712][RFC6347]
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5, //0x00, 0x29   Y[RFC2712]
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5, //0x00, 0x2A   Y[RFC2712]
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5,    // 0x00, 0x2B   N[RFC2712][RFC6347]
    TLS_PSK_WITH_NULL_SHA,              // 0x00, 0x2C   Y[RFC4785]
    TLS_DHE_PSK_WITH_NULL_SHA,          // 0x00, 0x2D   Y[RFC4785]
    TLS_RSA_PSK_WITH_NULL_SHA,          // 0x00, 0x2E   Y[RFC4785]
    TLS_RSA_WITH_AES_128_CBC_SHA,       // 0x00, 0x2F   Y[RFC5246]
    TLS_DH_DSS_WITH_AES_128_CBC_SHA,    // 0x00, 0x30   Y[RFC5246]
    TLS_DH_RSA_WITH_AES_128_CBC_SHA,    // 0x00, 0x31   Y[RFC5246]
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA,   // 0x00, 0x32   Y[RFC5246]
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA,   // 0x00, 0x33   Y[RFC5246]
    TLS_DH_anon_WITH_AES_128_CBC_SHA,   // 0x00, 0x34   Y[RFC5246]
    TLS_RSA_WITH_AES_256_CBC_SHA,       // 0x00, 0x35   Y[RFC5246]
    TLS_DH_DSS_WITH_AES_256_CBC_SHA,    // 0x00, 0x36   Y[RFC5246]
    TLS_DH_RSA_WITH_AES_256_CBC_SHA,    // 0x00, 0x37   Y[RFC5246]
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA,   // 0x00, 0x38   Y[RFC5246]
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA,   // 0x00, 0x39   Y[RFC5246]
    TLS_DH_anon_WITH_AES_256_CBC_SHA,   // 0x00, 0x3A   Y[RFC5246]
    TLS_RSA_WITH_NULL_SHA256,           // 0x00, 0x3B   Y[RFC5246]
    TLS_RSA_WITH_AES_128_CBC_SHA256,    // 0x00, 0x3C   Y[RFC5246]
    TLS_RSA_WITH_AES_256_CBC_SHA256,    // 0x00, 0x3D   Y[RFC5246]
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256, // 0x00, 0x3E   Y[RFC5246]
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256, // 0x00, 0x3F   Y[RFC5246]
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, //0x00, 0x40   Y[RFC5246]
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,  // 0x00, 0x41   Y[RFC5932]
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,//0x00, 0x42   Y[RFC5932]
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,//0x00, 0x43   Y[RFC5932]
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,//0x00,0x44   Y[RFC5932]
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,//0x00,0x45   Y[RFC5932]
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,//0x00,0x46   Y[RFC5932]
    // 0x00, 0x47 - 4F	Reserved to avoid conflicts with deployed implementations[Pasi_Eronen]
    // 0x00, 0x50 - 58	Reserved to avoid conflicts[Pasi Eronen, <pasi.eronen&nokia.com>, 2008 - 04 - 04. 2008 - 04 - 04]
    // 0x00, 0x59 - 5C	Reserved to avoid conflicts with deployed implementations[Pasi_Eronen]
    // 0x00, 0x5D - 5F	Unassigned
    // 0x00, 0x60 - 66	Reserved to avoid conflicts with widely deployed implementations[Pasi_Eronen]
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256=0x67,//0x00,0x67		Y[RFC5246]
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256, // 0x00, 0x68   Y[RFC5246]
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256, // 0x00, 0x69   Y[RFC5246]
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,// 0x00, 0x6A   Y[RFC5246]
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,// 0x00, 0x6B   Y[RFC5246]
    TLS_DH_anon_WITH_AES_128_CBC_SHA256,// 0x00, 0x6C   Y[RFC5246]
    TLS_DH_anon_WITH_AES_256_CBC_SHA256,// 0x00, 0x6D   Y[RFC5246]
    // 0x00, 0x6E - 83	Unassigned
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0084, //0x00,0x84   Y[RFC5932]
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,//0x00, 0x85   Y[RFC5932]
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,//0x00, 0x86   Y[RFC5932]
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,//0x00,0x87   Y[RFC5932]
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,//0x00,0x88   Y[RFC5932]
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,//0x00,0x89   Y[RFC5932]
    TLS_PSK_WITH_RC4_128_SHA,           // 0x00, 0x8A   N[RFC4279][RFC6347]
    TLS_PSK_WITH_3DES_EDE_CBC_SHA,      // 0x00, 0x8B   Y[RFC4279]
    TLS_PSK_WITH_AES_128_CBC_SHA,       // 0x00, 0x8C   Y[RFC4279]
    TLS_PSK_WITH_AES_256_CBC_SHA,       // 0x00, 0x8D   Y[RFC4279]
    TLS_DHE_PSK_WITH_RC4_128_SHA,       // 0x00, 0x8E   N[RFC4279][RFC6347]
    TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,  // 0x00, 0x8F   Y[RFC4279]
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA,   // 0x00, 0x90   Y[RFC4279]
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA,   // 0x00, 0x91   Y[RFC4279]
    TLS_RSA_PSK_WITH_RC4_128_SHA,       // 0x00, 0x92   N[RFC4279][RFC6347]
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,  // 0x00, 0x93   Y[RFC4279]
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA,   // 0x00, 0x94   Y[RFC4279]
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA,   // 0x00, 0x95   Y[RFC4279]
    TLS_RSA_WITH_SEED_CBC_SHA,          // 0x00, 0x96   Y[RFC4162]
    TLS_DH_DSS_WITH_SEED_CBC_SHA,       // 0x00, 0x97   Y[RFC4162]
    TLS_DH_RSA_WITH_SEED_CBC_SHA,       // 0x00, 0x98   Y[RFC4162]
    TLS_DHE_DSS_WITH_SEED_CBC_SHA,      // 0x00, 0x99   Y[RFC4162]
    TLS_DHE_RSA_WITH_SEED_CBC_SHA,      // 0x00, 0x9A   Y[RFC4162]
    TLS_DH_anon_WITH_SEED_CBC_SHA,      // 0x00, 0x9B   Y[RFC4162]
    TLS_RSA_WITH_AES_128_GCM_SHA256,    // 0x00, 0x9C   Y[RFC5288]
    TLS_RSA_WITH_AES_256_GCM_SHA384,    // 0x00, 0x9D   Y[RFC5288]
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,// 0x00, 0x9E   Y[RFC5288]
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, //0x00, 0x9F   Y[RFC5288]
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256, // 0x00, 0xA0   Y[RFC5288]
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384, // 0x00, 0xA1   Y[RFC5288]
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256, //0x00, 0xA2   Y[RFC5288]
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384, //0x00, 0xA3   Y[RFC5288]
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256, // 0x00, 0xA4   Y[RFC5288]
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384, // 0x00, 0xA5   Y[RFC5288]
    TLS_DH_anon_WITH_AES_128_GCM_SHA256, //0x00, 0xA6   Y[RFC5288]
    TLS_DH_anon_WITH_AES_256_GCM_SHA384, //0x00, 0xA7   Y[RFC5288]
    TLS_PSK_WITH_AES_128_GCM_SHA256,    // 0x00, 0xA8   Y[RFC5487]
    TLS_PSK_WITH_AES_256_GCM_SHA384,    // 0x00, 0xA9   Y[RFC5487]
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256, //0x00, 0xAA   Y[RFC5487]
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384, //0x00, 0xAB   Y[RFC5487]
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256, //0x00, 0xAC   Y[RFC5487]
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384, //0x00, 0xAD   Y[RFC5487]
    TLS_PSK_WITH_AES_128_CBC_SHA256,    // 0x00, 0xAE   Y[RFC5487]
    TLS_PSK_WITH_AES_256_CBC_SHA384,    // 0x00, 0xAF   Y[RFC5487]
    TLS_PSK_WITH_NULL_SHA256,           // 0x00, 0xB0   Y[RFC5487]
    TLS_PSK_WITH_NULL_SHA384,           // 0x00, 0xB1   Y[RFC5487]
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, //0x00, 0xB2   Y[RFC5487]
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384, //0x00, 0xB3   Y[RFC5487]
    TLS_DHE_PSK_WITH_NULL_SHA256,       // 0x00, 0xB4   Y[RFC5487]
    TLS_DHE_PSK_WITH_NULL_SHA384,       // 0x00, 0xB5   Y[RFC5487]
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256, //0x00, 0xB6   Y[RFC5487]
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384, //0x00, 0xB7   Y[RFC5487]
    TLS_RSA_PSK_WITH_NULL_SHA256,       // 0x00, 0xB8   Y[RFC5487]
    TLS_RSA_PSK_WITH_NULL_SHA384,       // 0x00, 0xB9   Y[RFC5487]
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,//0x00, 0xBA   Y[RFC5932]
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256, //0x00,0xBB   Y[RFC5932]
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256, //0x00,0xBC   Y[RFC5932]
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,//0x00,0xBD   Y[RFC5932]
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,//0x00,0xBE   Y[RFC5932]
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,//0x00,0xBF   Y[RFC5932]
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,    //0x00,0xC0   Y[RFC5932]
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256, //0x00,0xC1   Y[RFC5932]
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256, //0x00,0xC2   Y[RFC5932]
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,//0x00,0xC3   Y[RFC5932]
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,//0x00,0xC4   Y[RFC5932]
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,//0x00,0xC5   Y[RFC5932]
    //0x00, 0xC6 - FE	Unassigned
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV=0x00FF,//0x00,0xFF   Y[RFC5746]

    // These are new ciphers in TLS1.3. See RFC5116, RFC8439, RFC6655 and RFC8446#ref-SHS
    TLS_AES_128_GCM_SHA256 = 0x1301,        // 0x13, 0x01 RFC8446 Appendix-B.4
    TLS_AES_256_GCM_SHA384 = 0x1302,        // 0x13, 0x02 RFC8446 Appendix-B.4
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,  // 0x13, 0x03 RFC8446 Appendix-B.4
    TLS_AES_128_CCM_SHA256 = 0x1304,        // 0x13, 0x04 RFC8446 Appendix-B.4
    TLS_AES_128_CCM_8_SHA256 = 0x1305,      // 0x13, 0x05 RFC8446 Appendix-B.4

    //0x01 - 55, *Unassigned
    TLS_FALLBACK_SCSV=0x5600,           // 0x56, 0x00   Y[RFC7507]
    TLS_UNASSIGNED_0xC000 = 0xC000,     // 0x56, 0x01 - 0xC0, 0x00   Unassigned
    TLS_ECDH_ECDSA_WITH_NULL_SHA,       // 0xC0, 0x01   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA,    // 0xC0, 0x02   N[RFC - ietf - tls - rfc4492bis - 17][RFC6347]
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,//0xC0, 0x03   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, //0xC0, 0x04   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, //0xC0, 0x05   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDHE_ECDSA_WITH_NULL_SHA,      // 0xC0, 0x06   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,   // 0xC0, 0x07   N[RFC - ietf - tls - rfc4492bis - 17][RFC6347]
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,//0xC0,0x08   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, //0xC0,0x09   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, //0xC0,0x0A   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDH_RSA_WITH_NULL_SHA,         // 0xC0, 0x0B   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDH_RSA_WITH_RC4_128_SHA,      // 0xC0, 0x0C   N[RFC - ietf - tls - rfc4492bis - 17][RFC6347]
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, // 0xC0, 0x0D   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,  // 0xC0, 0x0E   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,  // 0xC0, 0x0F   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDHE_RSA_WITH_NULL_SHA,        // 0xC0, 0x10   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDHE_RSA_WITH_RC4_128_SHA,     // 0xC0, 0x11   N[RFC - ietf - tls - rfc4492bis - 17][RFC6347]
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, //0xC0, 0x12   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, // 0xC0, 0x13   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, // 0xC0, 0x14   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDH_anon_WITH_NULL_SHA,        // 0xC0, 0x15   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDH_anon_WITH_RC4_128_SHA,     // 0xC0, 0x16   N[RFC - ietf - tls - rfc4492bis - 17][RFC6347]
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA, //0xC0, 0x17   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA, // 0xC0, 0x18   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA, // 0xC0, 0x19   Y[RFC - ietf - tls - rfc4492bis - 17]
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,  // 0xC0, 0x1A   Y[RFC5054]
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,//0xC0,0x1B   Y[RFC5054]
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,//0xC0,0x1C   Y[RFC5054]
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA,   // 0xC0, 0x1D   Y[RFC5054]
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,//0xC0, 0x1E   Y[RFC5054]
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,//0xC0, 0x1F   Y[RFC5054]
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA,   // 0xC0, 0x20   Y[RFC5054]
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,//0xC0, 0x21   Y[RFC5054]
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,//0xC0, 0x22   Y[RFC5054]
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,//0xC0,0x23   Y[RFC5289]
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,//0xC0,0x24   Y[RFC5289]
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, //0xC0,0x25   Y[RFC5289]
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384, //0xC0,0x26   Y[RFC5289]
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,  //0xC0,0x27   Y[RFC5289]
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,  //0xC0,0x28   Y[RFC5289]
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,//0xC0, 0x29   Y[RFC5289]
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,//0xC0, 0x2A   Y[RFC5289]
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,//0xC0,0x2B   Y[RFC5289]
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,//0xC0,0x2C   Y[RFC5289]
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, //0xC0,0x2D   Y[RFC5289]
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384, //0xC0,0x2E   Y[RFC5289]
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,  //0xC0,0x2F   Y[RFC5289]
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,  //0xC0,0x30   Y[RFC5289]
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256, // 0xC0, 0x31   Y[RFC5289]
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384, // 0xC0, 0x32   Y[RFC5289]
    TLS_ECDHE_PSK_WITH_RC4_128_SHA,     // 0xC0, 0x33   N[RFC5489][RFC6347]
    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA, //0xC0, 0x34   Y[RFC5489]
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA, // 0xC0, 0x35   Y[RFC5489]
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA, // 0xC0, 0x36   Y[RFC5489]
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,//0xC0,0x37   Y[RFC5489]
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,//0xC0,0x38   Y[RFC5489]
    TLS_ECDHE_PSK_WITH_NULL_SHA,        // 0xC0, 0x39   Y[RFC5489]
    TLS_ECDHE_PSK_WITH_NULL_SHA256,     // 0xC0, 0x3A   Y[RFC5489]
    TLS_ECDHE_PSK_WITH_NULL_SHA384,     // 0xC0, 0x3B   Y[RFC5489]
    TLS_RSA_WITH_ARIA_128_CBC_SHA256,   // 0xC0, 0x3C   Y[RFC6209]
    TLS_RSA_WITH_ARIA_256_CBC_SHA384,   // 0xC0, 0x3D   Y[RFC6209]
    TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256, //0xC0, 0x3E   Y[RFC6209]
    TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384, //0xC0, 0x3F   Y[RFC6209]
    TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256, //0xC0, 0x40   Y[RFC6209]
    TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384, //0xC0, 0x41   Y[RFC6209]
    TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256,//0xC0, 0x42   Y[RFC6209]
    TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384,//0xC0, 0x43   Y[RFC6209]
    TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,//0xC0, 0x44   Y[RFC6209]
    TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,//0xC0, 0x45   Y[RFC6209]
    TLS_DH_anon_WITH_ARIA_128_CBC_SHA256,//0xC0, 0x46   Y[RFC6209]
    TLS_DH_anon_WITH_ARIA_256_CBC_SHA384,//0xC0, 0x47   Y[RFC6209]
    TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,//0xC0, 0x48   Y[RFC6209]
    TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,//0xC0, 0x49   Y[RFC6209]
    TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256, //0xC0, 0x4A   Y[RFC6209]
    TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384, //0xC0, 0x4B   Y[RFC6209]
    TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256, // 0xC0, 0x4C   Y[RFC6209]
    TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384, // 0xC0, 0x4D   Y[RFC6209]
    TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,  // 0xC0, 0x4E   Y[RFC6209]
    TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,  // 0xC0, 0x4F   Y[RFC6209]
    TLS_RSA_WITH_ARIA_128_GCM_SHA256,   // 0xC0, 0x50   Y[RFC6209]
    TLS_RSA_WITH_ARIA_256_GCM_SHA384,   // 0xC0, 0x51   Y[RFC6209]
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,//0xC0, 0x52   Y[RFC6209]
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,//0xC0, 0x53   Y[RFC6209]
    TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256, //0xC0, 0x54   Y[RFC6209]
    TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384, //0xC0, 0x55   Y[RFC6209]
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256,//0xC0, 0x56   Y[RFC6209]
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384,//0xC0, 0x57   Y[RFC6209]
    TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256, //0xC0, 0x58   Y[RFC6209]
    TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384, //0xC0, 0x59   Y[RFC6209]
    TLS_DH_anon_WITH_ARIA_128_GCM_SHA256,//0xC0, 0x5A   Y[RFC6209]
    TLS_DH_anon_WITH_ARIA_256_GCM_SHA384,//0xC0, 0x5B   Y[RFC6209]
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,//0xC0, 0x5C   Y[RFC6209]
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,//0xC0, 0x5D   Y[RFC6209]
    TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256, //0xC0, 0x5E   Y[RFC6209]
    TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384, //0xC0, 0x5F   Y[RFC6209]
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256, // 0xC0, 0x60   Y[RFC6209]
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384, // 0xC0, 0x61   Y[RFC6209]
    TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,  // 0xC0, 0x62   Y[RFC6209]
    TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,  // 0xC0, 0x63   Y[RFC6209]
    TLS_PSK_WITH_ARIA_128_CBC_SHA256,   // 0xC0, 0x64   Y[RFC6209]
    TLS_PSK_WITH_ARIA_256_CBC_SHA384,   // 0xC0, 0x65   Y[RFC6209]
    TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,//0xC0, 0x66   Y[RFC6209]
    TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,//0xC0, 0x67   Y[RFC6209]
    TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,//0xC0, 0x68   Y[RFC6209]
    TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,//0xC0, 0x69   Y[RFC6209]
    TLS_PSK_WITH_ARIA_128_GCM_SHA256,   // 0xC0, 0x6A   Y[RFC6209]
    TLS_PSK_WITH_ARIA_256_GCM_SHA384,   // 0xC0, 0x6B   Y[RFC6209]
    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,//0xC0, 0x6C   Y[RFC6209]
    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,//0xC0, 0x6D   Y[RFC6209]
    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,//0xC0, 0x6E   Y[RFC6209]
    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,//0xC0, 0x6F   Y[RFC6209]
    TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,//0xC0, 0x70   Y[RFC6209]
    TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,//0xC0, 0x71   Y[RFC6209]
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,//0xC0,0x72  Y[RFC6367]
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,//0xC0 0x73  Y[RFC6367]
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256, //0xC0,0x74 Y[RFC6367]
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384, //0xC0,0x75 Y[RFC6367]
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256, // 0xC0,0x76 Y[RFC6367]
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384, // 0xC0,0x77 Y[RFC6367]
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256, // 0xC0, 0x78 Y[RFC6367]
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384, // 0xC0, 0x79 Y[RFC6367]
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256, // 0xC0, 0x7A   Y[RFC6367]
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384, // 0xC0, 0x7B   Y[RFC6367]
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256, // 0xC0, 0x7C Y[RFC6367]
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384, // 0xC0, 0x7D Y[RFC6367]
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256,  // 0xC0, 0x7E Y[RFC6367]
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384,  // 0xC0, 0x7F Y[RFC6367]
    TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256, // 0xC0, 0x80 Y[RFC6367]
    TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384, // 0xC0, 0x81 Y[RFC6367]
    TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256,  // 0xC0, 0x82 Y[RFC6367]
    TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384,  // 0xC0, 0x83 Y[RFC6367]
    TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256, // 0xC0, 0x84 Y[RFC6367]
    TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384, // 0xC0, 0x85 Y[RFC6367]
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,//0xC0,0x86 Y[RFC6367]
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,//0xC0,0x87 Y[RFC6367]
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256, //0xC0,0x88 Y[RFC6367]
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384, //0xC0,0x89 Y[RFC6367]
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,  //0xC0,0x8A Y[RFC6367]
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,  //0xC0,0x8B Y[RFC6367]
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,  // 0xC0,0x8C Y[RFC6367]
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,  // 0xC0,0x8D Y[RFC6367]
    TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,   // 0xC0, 0x8E   Y[RFC6367]
    TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,   // 0xC0, 0x8F   Y[RFC6367]
    TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,//0xC0, 0x90   Y[RFC6367]
    TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,//0xC0, 0x91   Y[RFC6367]
    TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,//0xC0, 0x92   Y[RFC6367]
    TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,//0xC0, 0x93   Y[RFC6367]
    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,   // 0xC0, 0x94   Y[RFC6367]
    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,   // 0xC0, 0x95   Y[RFC6367]
    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,//0xC0, 0x96   Y[RFC6367]
    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,//0xC0, 0x97   Y[RFC6367]
    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,//0xC0, 0x98   Y[RFC6367]
    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,//0xC0, 0x99   Y[RFC6367]
    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,//0xC0, 0x9A   Y[RFC6367]
    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,//0xC0, 0x9B   Y[RFC6367]
    TLS_RSA_WITH_AES_128_CCM,           // 0xC0, 0x9C   Y[RFC6655]
    TLS_RSA_WITH_AES_256_CCM,           // 0xC0, 0x9D   Y[RFC6655]
    TLS_DHE_RSA_WITH_AES_128_CCM,       // 0xC0, 0x9E   Y[RFC6655]
    TLS_DHE_RSA_WITH_AES_256_CCM,       // 0xC0, 0x9F   Y[RFC6655]
    TLS_RSA_WITH_AES_128_CCM_8,         // 0xC0, 0xA0   Y[RFC6655]
    TLS_RSA_WITH_AES_256_CCM_8,         // 0xC0, 0xA1   Y[RFC6655]
    TLS_DHE_RSA_WITH_AES_128_CCM_8,     // 0xC0, 0xA2   Y[RFC6655]
    TLS_DHE_RSA_WITH_AES_256_CCM_8,     // 0xC0, 0xA3   Y[RFC6655]
    TLS_PSK_WITH_AES_128_CCM,           // 0xC0, 0xA4   Y[RFC6655]
    TLS_PSK_WITH_AES_256_CCM,           // 0xC0, 0xA5   Y[RFC6655]
    TLS_DHE_PSK_WITH_AES_128_CCM,       // 0xC0, 0xA6   Y[RFC6655]
    TLS_DHE_PSK_WITH_AES_256_CCM,       // 0xC0, 0xA7   Y[RFC6655]
    TLS_PSK_WITH_AES_128_CCM_8,         // 0xC0, 0xA8   Y[RFC6655]
    TLS_PSK_WITH_AES_256_CCM_8,         // 0xC0, 0xA9   Y[RFC6655]
    TLS_PSK_DHE_WITH_AES_128_CCM_8,     // 0xC0, 0xAA   Y[RFC6655]
    TLS_PSK_DHE_WITH_AES_256_CCM_8,     // 0xC0, 0xAB   Y[RFC6655]
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM,   // 0xC0, 0xAC   Y[RFC7251]
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM,   // 0xC0, 0xAD   Y[RFC7251]
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, // 0xC0, 0xAE   Y[RFC7251]
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8, // 0xC0, 0xAF   Y[RFC7251]
    //0xC0, 0xB0 - FF	Unassigned
    //0xC1 - CB, *Unassigned
    //0xCC, 0x00 - A7	Unassigned
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256=0xCCA8, //0xCC,0xA8 Y[RFC7905]
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,  //0xCC, 0xA9  Y[RFC7905]
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,  // 0xCC, 0xAA   Y[RFC7905]
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,      // 0xCC, 0xAB   Y[RFC7905]
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,// 0xCC, 0xAC   Y[RFC7905]
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,  // 0xCC, 0xAD   Y[RFC7905]
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,  // 0xCC, 0xAE   Y[RFC7905]
    //0xCC, 0xAF - FF	Unassigned
    //0xCD - CF, *Unassigned
    TLS_UNASSIGNED_D000 = 0xD000,           // 0xD0, 0x00   Unassigned
    TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,  // 0xD0, 0x01   Y[RFC - ietf - tls - ecdhe - psk - aead - 05]
    TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,  // 0xD0, 0x02   Y[RFC - ietf - tls - ecdhe - psk - aead - 05]
    TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256,// 0xD0, 0x03   Y[RFC - ietf - tls - ecdhe - psk - aead - 05]
    TLS_UNASSIGNED_D004,                    // 0xD0, 0x04   Unassigned
    TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256,  // 0xD0, 0x05   Y[RFC - ietf - tls - ecdhe - psk - aead - 05]
    //0xD0, 0x06 - FF	Unassigned
    //0xD1 - FD, *Unassigned
    //0xFE, 0x00 - FD	Unassigned
    //0xFE, 0xFE - FF	Reserved to avoid conflicts with widely deployed implementations[Pasi_Eronen]
    //0xFF, 0x00 - FF	Reserved for Private Use[RFC5246]
    TLS_LAST=0xFFFF
} TLS_CIPHER;


// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
enum SSL_EXTENTION {
    EXT_SERVER_NAME = 0x0000,           // Type: server_name (0)
    EXT_SUPPORTED_GROUPS = 0x000A,      // Type: supported_groups (10) Y [RFC4492][RFC8422][RFC7748][RFC7919] https://tools.ietf.org/html/rfc8422#section-5.1.1
    EXT_EC_POINT_FORMATS = 0x000B,      // Type: ec_point_formats (11) Y [RFC8422] https://tools.ietf.org/html/rfc8422#section-5.1. https://tools.ietf.org/html/rfc4492#section-5.1.2
    EXT_SIGNATURE_ALGORITHMS = 0x000D,  // Type: signature_algorithms (13)

    EXT_ENCRYPT_THEN_MAC = 0x0016,      // Type: encrypt_then_mac(22)
    EXT_EXTENDED_MASTER_SECRET = 0x0017,// Type: extended_master_secret (23)
    EXT_RECORD_SIZE_LIMIT = 0x001C,     // Type: 28	record_size_limit CH, EE Y [RFC8449]
    EXT_SESSIONTICKET_TLS = 0x0023,     // Type: SessionTicket TLS(35)

    EXT_PRESHARED_KEY = 0x0029,         // Type: 41	pre_shared_key CH, SH Y [RFC8446]
    EXT_SUPPORTED_VERSION = 0x002B,     // Type: supported_versions	CH, SH, HRR	Y [RFC8446]
    EXT_PSK_KEY_EXCHANGE_MODES = 0x002D,// Type: psk_key_exchange_modes	CH	Y [RFC8446]
    EXT_KEY_SHARE = 0x0033,             // Type: key_share	CH, SH, HRR	Y [RFC8446]

    EXT_RENEGOTIATION_INFO = 0xFF01,    // Type: renegotiation_info(65281)

    EXT_LAST = 0x7FFF
};

// https://tools.ietf.org/html/rfc4492#section-5.1.1
// https://tools.ietf.org/html/rfc8422#section-5.1.1
// https://tools.ietf.org/html/rfc7919
enum ECC_GROUP {
    ECC_NONE = 0,   // No ECC Support. It is also used to imply RSA
    ECC_secp256k1 = 0x0016, // Supported Group: secp256k1(0x0016)
    ECC_secp256r1 = 0x0017, // Supported Group: secp256r1(0x0017)
    ECC_secp384r1 = 0x0018, // Supported Group: secp384r1 (0x0018)
    ECC_secp521r1 = 0x0019, // Supported Group: secp521r1 (0x0019)
    ECC_x25519    = 0x001D, // Supported Group: x25519 (0x001d)
    ECC_x448      = 0x001E, // Supported Group: x448 (0x001e)
    ECC_ffdhe2048 = 0x0100, // Supported Group: ffdhe2048 (0x0100) RFC7919
    ECC_ffdhe3072 = 0x0101, // Supported Group: ffdhe3072 (0x0101) RFC7919
    ECC_ffdhe4096 = 0x0102, // Supported Group: ffdhe4096 (0x0102) RFC7919
    ECC_ffdhe6144 = 0x0103, // Supported Group: ffdhe6144 (0x0103) RFC7919
    ECC_ffdhe8192 = 0x0104, // Supported Group: ffdhe8192 (0x0104) RFC7919
    ECC_LAST = 0x7FFF
};

// RFC8446 sec 4.2.3: https://tools.ietf.org/html/rfc8446#section-4.2.3
enum SIG_ALG {
    // RSASSA-PKCS1-v1_5 algorithms
    rsa_pkcs1_sha256 = 0x0401,      // Signature Algorithm: rsa_pkcs1_sha256 (0x0401)
    rsa_pkcs1_sha384 = 0x0501,      // Signature Algorithm: rsa_pkcs1_sha384 (0x0501)
    rsa_pkcs1_sha512 = 0x0601,      // Signature Algorithm: rsa_pkcs1_sha512 (0x0601)

    // ECDSA algorithms
    ecdsa_secp256r1_sha256 = 0x0403, // Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
    ecdsa_secp384r1_sha384 = 0x0503, // Signature Algorithm: ecdsa_secp384r1_sha384 (0x0503)
    ecdsa_secp521r1_sha512 = 0x0603, // Signature Algorithm: ecdsa_secp521r1_sha512 (0x0603)

    // RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = 0x0804,   // Signature Algorithm: rsa_pss_rsae_sha256 (0x0804)
    rsa_pss_rsae_sha384 = 0x0805,   // Signature Algorithm: rsa_pss_rsae_sha384 (0x0805)
    rsa_pss_rsae_sha512 = 0x0806,   // Signature Algorithm: rsa_pss_rsae_sha512 (0x0806)

    // EdDSA algorithms
    ed25519 = 0x0807,               // Signature Algorithm: ed25519(0x0807),
    ed448 = 0x0808,                 // Signature Algorithm: ed448(0x0808),

    // RSASSA-PSS algorithms with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = 0x0809,    // Signature Algorithm: rsa_pss_pss_sha256(0x0809),
    rsa_pss_pss_sha384 = 0x080a,    // Signature Algorithm: rsa_pss_pss_sha384(0x080a),
    rsa_pss_pss_sha512 = 0x080b,    // Signature Algorithm: rsa_pss_pss_sha512(0x080b),

    // Legacy algorithms
    rsa_pkcs1_sha1 = 0x0201,    // Signature Algorithm: rsa_pkcs1_sha1 (0x0201)
    ecdsa_sha1 = 0x0203,        // Signature Algorithm: ecdsa_sha1 (0x0203)

    // Obsolete and not used in TLS 1.3
    SHA1_DSA = 0x0202,          // Signature Algorithm: SHA1 DSA (0x0202)
    SHA256_DSA = 0x0402,        // Signature Algorithm: SHA256 DSA (0x0402)
    SHA384_DSA = 0x0502,        // Signature Algorithm: SHA384 DSA (0x0502)
    SHA512_DSA = 0x0602,        // Signature Algorithm: SHA512 DSA (0x0602)
    SIGALG_NONE = 0x0000,       // Signature Algorithm Not Supported.

    SIGALG_LAST = 0x7FFF
};




struct TLSCertificate {
    unsigned short version;
    unsigned int algorithm;
    unsigned int key_algorithm;
    unsigned int ec_algorithm;
    unsigned char *exponent;
    unsigned int exponent_len;
    unsigned char *pk;
    unsigned int pk_len;
    unsigned char *priv;
    unsigned int priv_len;
    unsigned char *issuer_country;
    unsigned char *issuer_state;
    unsigned char *issuer_location;
    unsigned char *issuer_entity;
    unsigned char *issuer_subject;
    unsigned char *not_before;
    unsigned char *not_after;
    unsigned char *country;
    unsigned char *state;
    unsigned char *location;
    unsigned char *entity;
    unsigned char *subject;
    unsigned char **san;
    unsigned short san_length;
    unsigned char *ocsp;
    unsigned char *serial_number;
    unsigned int serial_len;
    unsigned char *sign_key;
    unsigned int sign_len;
    unsigned char *fingerprint;
    unsigned char *der_bytes;
    unsigned int der_len;
    unsigned char *bytes;
    unsigned int len;
};

struct _private_OID_chain {
    void *top;
    unsigned char *oid;
};