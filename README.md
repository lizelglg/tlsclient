# tlsclient
tls1.2/1.3


curve25519.c not using
libtomcrypt.c not using

A tls library, client code. If you need to create a server, you can refer to the code to modify the logic of sending and receiving messages from the client. The code is all in tlsclient.cpp

The working environment is vs2013(x86/x64), and using it only requires including "tlsclient. cpp"

Referring to "tlse", there is no certificate verification and supports tls1.2 and tls1.3
This code is for my excessive product of programmatic trading Binance, so I did not perform certificate verification (remote server or antique Windows Server 2008, unable to use the built-in HTTP library of Windows)
If certificate verification is required, you can refer to the following website to add code functionality
tls13.xargs.org

All encryption libraries were downloaded from GitHub, where sha2. c modified a calculation problem and gcm. c optimized the speed

Encryption suite support:

TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384,
TLS_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA2566
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
