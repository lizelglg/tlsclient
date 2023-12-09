#pragma once

#include <stdint.h>
#include "chacha20.c"
#include "tls.h"
#include "ecc.c"
#include "gcm.c"
#include "sha2.c"






class tlsbuf
{
public:
	char	*buf;
	int		buf_len;
	int		size;
	tlsbuf()
	{
		memset(this, 0, sizeof(*this));
	}
	~tlsbuf()
	{
		if(buf)
			delete[] buf;
	}

	int append(const void *data, int size)
	{
		check_size(size);
		memcpy(buf+this->size, data, size);
		this->size += size;
		return this->size - size;
	}
	template<class T>
	int append(T data)
	{
		return append(&data, sizeof(data));
	}
	int append_size(int size)
	{
		check_size(size);
		this->size += size;
		return this->size - size;
	}

	void set_size(int size)
	{
		this->size = 0;
		check_size(size);
		this->size = size;
	}

	void clear()
	{
		size = 0;
	}
	void check_size(int append_size)
	{
		if(size+append_size <= buf_len)
			return;
		
		char	*old_buf = buf;
		int		new_len = max((size+append_size)*4, 256);

		buf = new char[new_len];
		if(size > 0)
			memcpy(buf, old_buf, size);
		if(old_buf)
			delete[] old_buf;
		buf_len = new_len;
	}
};

class tlsbuf_reader
{
public:
	char *buf;
	int buf_size;
	int readed;
	tlsbuf_reader(char *buf, int size)
	{
		readed		= 0;
		buf_size	= size;
		this->buf	= buf;
	}
	template<class T>
	T read()
	{
		T v =  *(T*)(buf+readed);
		readed += sizeof(T);
		return v;
	}
	void read(char *out, int size)
	{
		memcpy(out, buf+readed, size);
		readed += size;
	}
};

void DumpData(const char* tag, const char* p, size_t cbSize)
{
	return;
    printf("%s:", tag);
    for (int i = 0; i < (int)cbSize; i++) {
        printf("%s%02X", (i&15)? " " : "\n    ", (unsigned char)p[i]);
    }
    printf("\n");
}




#define RAND_SIZE					32
#define MAX_PUBKEY_SIZE				2048
#define MAX_HASH_LEN				64
#define MAX_KEY_SIZE				32
#define MAX_IV_SIZE					12

enum tls_version
{
	tls12 = 0x303,
	tls13 = 0x304,
};

class tls_encoder
{
public:
	virtual ~tls_encoder()
	{
	}
	
	virtual bool init(unsigned char *local_key, unsigned char *remote_key, unsigned char *local_iv, unsigned char *remote_iv, int key_length, bool tls_13) = 0;
	virtual void encode(tlsbuf &out, const char *packet, int packet_size, const unsigned char *aad, int aad_size, bool tls_13) = 0;
	virtual char *decode(tlsbuf_reader &in, tlsbuf &out, const unsigned char *aad, int aad_size, bool tls_13) = 0;
	virtual int compute_size(int size, int encode_or_decode, bool tls_13) = 0;
	virtual int iv_len(bool tls_13) = 0;
};

class tls_encoder_aes:public tls_encoder
{
	static const		int iv_length			= 4;
	static const		int encryption_length	= 8;
	static const		int tag_length			= 16;
	unsigned char local_aead_iv[iv_length+encryption_length];
	unsigned char remote_aead_iv[iv_length+encryption_length];
	gcm_context		aes_gcm_local;
	gcm_context		aes_gcm_remote;
public:
	bool init(unsigned char *local_key, unsigned char *remote_key, unsigned char *local_iv, unsigned char *remote_iv, int key_length, bool tls_13)
	{
		int res1 = gcm_setkey(&aes_gcm_local, local_key, key_length);
		int res2 = gcm_setkey(&aes_gcm_remote, remote_key, key_length);
        memcpy(local_aead_iv, local_iv, iv_len(tls_13));
        memcpy(remote_aead_iv, remote_iv, iv_len(tls_13));

		return res1 == 0 && res2 == 0;
	}
	
	void encode(tlsbuf &out, const char *packet, int packet_size, const unsigned char *aad, int aad_size, bool tls_13)
	{
		unsigned char iv[iv_length+encryption_length];
		if(tls_13 == false)
		{
			memcpy(iv, local_aead_iv, iv_len(tls_13));
			for(int i = iv_length; i < iv_length+encryption_length; i++)
				iv[i] = rand()&0xff;
			out.append(iv + iv_length, encryption_length);
		}
		else
		{
			memcpy(iv, local_aead_iv, iv_len(tls_13));
			for (int i = iv_length; i < iv_length+encryption_length; i++)
				iv[i] = iv[i] ^ aad[aad_size-encryption_length+i-iv_length];
			aad_size -= encryption_length;
		}


		out.append_size(packet_size);
		int ret = 0;
		ret = gcm_start(&aes_gcm_local, ENCRYPT, iv, iv_length+encryption_length, aad, aad_size);
		ret = gcm_update(&aes_gcm_local, packet_size, (unsigned char*)packet, (unsigned char*)out.buf + out.size - packet_size);
		out.append_size(tag_length);
		ret = gcm_finish(&aes_gcm_local, (unsigned char*)out.buf + out.size - tag_length, tag_length);
	}

	char *decode(tlsbuf_reader &in, tlsbuf &out, const unsigned char *aad, int aad_size, bool tls_13)
	{
		int decode_length = compute_size(in.buf_size, 1, tls_13);

		unsigned char iv[iv_length+encryption_length];
		if(tls_13 == false)
		{
			memcpy(remote_aead_iv + iv_length, in.buf, encryption_length);
			memcpy(iv, remote_aead_iv, iv_length+encryption_length);
		}
		else
		{
			memcpy(iv, remote_aead_iv, iv_len(tls_13));
			for (int i = iv_length; i < iv_length+encryption_length; i++)
				iv[i] = iv[i] ^ aad[aad_size-encryption_length+i-iv_length];
			aad_size -= encryption_length;
		}
		
		out.set_size(decode_length);
		unsigned char tag[tag_length];
		int ret1 = gcm_start(&aes_gcm_remote, DECRYPT, iv, sizeof(iv), aad, aad_size);
		int ret2 = gcm_update(&aes_gcm_remote, decode_length, (unsigned char*)in.buf + (tls_13 ? 0 : encryption_length), (unsigned char*)out.buf);
		int ret3 = gcm_finish(&aes_gcm_remote, (unsigned char*)tag, tag_length);

        if ((ret1) || (ret2) || (ret3)) 
			return "错误的包";
        // check tag
        if (memcmp(in.buf + (tls_13 ? 0 : encryption_length) + decode_length, tag, tag_length) )
			return "数据校验失败";
		return 0;
	}
	virtual int compute_size(int size, int encode_or_decode, bool tls_13)
	{
		if(encode_or_decode == 1)
			return tls_13 ? size - tag_length : size - tag_length - encryption_length;
		else
			return tls_13 ? size + tag_length : size + tag_length + encryption_length;
	}
	virtual int iv_len(bool tls_13)
	{
		return tls_13 ? iv_length + encryption_length : iv_length;
	}
};



static tls_encoder *create_encoder_aes()
{
	return new tls_encoder_aes();
}
class tls_encoder_chacha20:public tls_encoder
{
	static const int iv_length = TLS_CHACHA20_IV_LENGTH;
	chacha_ctx chacha_local;
	chacha_ctx chacha_remote;
	unsigned char remote_nonce[iv_length];
	unsigned char local_nonce[iv_length];
public:
	bool init(unsigned char *local_key, unsigned char *remote_key, unsigned char *local_iv, unsigned char *remote_iv, int key_length, bool tls_13)
	{
        unsigned int counter = 1;
        chacha_keysetup(&chacha_local, local_key, key_length * 8);
        chacha_keysetup(&chacha_remote, remote_key, key_length * 8);
        chacha_ivsetup_96bitnonce(&chacha_local, local_iv, (unsigned char *)&counter);
		memcpy(local_nonce, local_iv, iv_length);
        chacha_ivsetup_96bitnonce(&chacha_remote, remote_iv, (unsigned char *)&counter);
		memcpy(remote_nonce, remote_iv, iv_length);
		return true;
	}
	void encode(tlsbuf &out, const char *packet, int packet_size, const unsigned char *aad, int aad_size, bool tls_13)
	{
		const unsigned char *sequence = tls_13 ? aad + 5 : aad;
		if(tls_13)
			aad_size = 5;

		int counter = 1;
		out.append_size(packet_size+POLY1305_TAGLEN);
		unsigned char poly1305_key[POLY1305_KEYLEN];
		chacha_ivupdate(&chacha_local, local_nonce, sequence, (u8 *)&counter);
		chacha20_poly1305_key(&chacha_local, poly1305_key);
		chacha20_poly1305_aead(&chacha_local, (u8*)packet, packet_size, (u8*)aad, aad_size, poly1305_key, (u8*)out.buf + out.size-POLY1305_TAGLEN-packet_size);

	}

	
	char *decode(tlsbuf_reader &in, tlsbuf &out, const unsigned char *aad, int aad_size, bool tls_13)
	{
		out.check_size(in.buf_size);

		const unsigned char *sequence = tls_13 ? aad + 5 : aad;
		if(tls_13)
			aad_size = 5;

		unsigned int counter = 1;
		chacha_ivupdate(&chacha_remote, remote_nonce, (u8*)sequence, (unsigned char *)&counter);
		unsigned char poly1305_key[POLY1305_KEYLEN];
		chacha20_poly1305_key(&chacha_remote, poly1305_key);
		int size = chacha20_poly1305_decode(&chacha_remote, (u8*)in.buf, in.buf_size, (u8*)aad, aad_size, poly1305_key, (u8*)out.buf);
		if(size <= 0)
			return "数据校验失败";
		out.size = size;
		return 0;
	}
	virtual int compute_size(int size, int encode_or_decode, bool tls_13)
	{
		return encode_or_decode == 1 ? size - POLY1305_TAGLEN : size + POLY1305_TAGLEN;
	}
	virtual int iv_len(bool tls_13)
	{
		return iv_length;
	}
};
static tls_encoder *create_encoder_chacha20()
{
	return new tls_encoder_chacha20();
}


class tls_hash
{
	tlsbuf	cache;
public:
	void reset()
	{
		cache.clear();
	}
	void append(const char *buf, int size)
	{
		cache.append(buf, size);
	}

	void get_hash(const char *out, int hash_size)
	{
		if(hash_size == 32)
		{
			sha256_ctx ctx;
			sha256_init(&ctx);
			if(cache.size > 0)
				sha256_update(&ctx, (u8*)cache.buf, cache.size);
			sha256_final(&ctx, (u8*)out);
		}
		else
		{
			sha384_ctx ctx;
			sha384_init(&ctx);
			if(cache.size > 0)
				sha384_update(&ctx, (u8*)cache.buf, cache.size);
			sha384_final(&ctx, (u8*)out);
		}
	}
};

class tls_hmac
{
	int hash_size;
	union
	{
		hmac_sha256_ctx ctx256;
		hmac_sha384_ctx ctx384;
	};
public:
	tls_hmac(int hash_size, const unsigned char *key, unsigned int key_size)
	{
		this->hash_size = hash_size;
		if(hash_size == 32)
			hmac_sha256_init(&ctx256, key, key_size);
		else
			hmac_sha384_init(&ctx384, key, key_size);
	}
	void update(const unsigned char *message, unsigned int message_len)
	{
		if(hash_size == 32)
			hmac_sha256_update(&ctx256, message, message_len);
		else
			hmac_sha384_update(&ctx384, message, message_len);
	}
	void done(unsigned char *mac, unsigned int mac_size)
	{
		if(hash_size == 32)
			hmac_sha256_final(&ctx256, mac, mac_size);
		else
			hmac_sha384_final(&ctx384, mac, mac_size);
	}
};


class tls_cipher
{
	int _private_tls_hkdf_label(const char *label, unsigned char label_len, const unsigned char *data, unsigned char data_len, unsigned char *hkdflabel, unsigned short length, const char *prefix = "tls13 ") {
		*(unsigned short *)hkdflabel = htons(length);
		int prefix_len = (int)strlen(prefix);
		memcpy(&hkdflabel[3], prefix, prefix_len);

		hkdflabel[2] = (unsigned char)prefix_len + label_len;
		memcpy(&hkdflabel[3 + prefix_len], label, label_len);
		hkdflabel[3 + prefix_len + label_len] = (unsigned char)data_len;
		if (data_len)
			memcpy(&hkdflabel[4 + prefix_len + label_len], data, data_len);
		return 4 + prefix_len + label_len + data_len;
	}

	void _private_tls_hkdf_extract(unsigned char *output, unsigned int outlen, const unsigned char *salt, unsigned int salt_len, const unsigned char *ikm, unsigned char ikm_len) {

		static unsigned char dummy_label[1] = { 0 };
		if ((!salt) || (salt_len == 0)) {
			salt_len = 1;
			salt = dummy_label;
		}
		tls_hmac hmac(chiper_list()[cipher_index].hash_len, salt, salt_len);
		hmac.update(ikm, ikm_len);
		hmac.done(output, outlen);
	}

	void _private_tls_hkdf_expand(unsigned char *output, unsigned int outlen, const unsigned char *secret, unsigned int secret_len, const unsigned char *info, unsigned char info_len) {
		unsigned char	digest_out[MAX_HASH_LEN];
		unsigned int	idx = 0;
		unsigned char	i2 = 0;
		unsigned int	hash_len = chiper_list()[cipher_index].hash_len;
		while (outlen) {
			tls_hmac hmac(hash_len, secret, secret_len);
			if (i2)
				hmac.update(digest_out, hash_len);
			if ((info) && (info_len))
				hmac.update(info, info_len);
			i2++;
			hmac.update(&i2, 1);
			hmac.done(digest_out, hash_len);
            
			unsigned int copylen = outlen;
			if (copylen > hash_len)
				copylen = (unsigned int)hash_len;
            
			for (unsigned int i = 0; i < copylen; i++) {
				output[idx++] = digest_out[i];
				outlen--;
			}
            
			if (!outlen)
				break;            
		}
	}

	void _private_tls_hkdf_expand_label(unsigned char *output, unsigned int outlen, const unsigned char *secret, unsigned int secret_len, const char *label, unsigned char label_len, const unsigned char *data, unsigned char data_len) {
		unsigned char hkdf_label[512];
		int len = _private_tls_hkdf_label(label, label_len, data, data_len, hkdf_label, outlen);
		_private_tls_hkdf_expand(output, outlen, secret, secret_len, hkdf_label, len);
	}

	void _private_tls_prf(char *output, unsigned int outlen, const char *secret, const unsigned int secret_len,
						   const char *label, unsigned int label_len, char *seed, unsigned int seed_len,
						   unsigned char *seed_b, unsigned int seed_b_len)
	{
		{
			// sha256_hmac
			unsigned char digest_out0[MAX_HASH_LEN];
			unsigned char digest_out1[MAX_HASH_LEN];
			unsigned int i;
        
			unsigned int hash_len = chiper_list()[cipher_index].hash_len;
			tls_hmac hmac(hash_len, (u8*)secret, secret_len);
			hmac.update( (unsigned char*)label, label_len);
			hmac.update((unsigned char*)seed, seed_len);
			if ((seed_b) && (seed_b_len))
				hmac.update((unsigned char*)seed_b, seed_b_len);
			hmac.done(digest_out0, hash_len);
			int idx = 0;
			while (outlen) {
				tls_hmac hmac(hash_len, (u8*)secret, secret_len);
				hmac.update( digest_out0, hash_len);
				hmac.update( (u8*)label, label_len);
				hmac.update((u8*)seed, seed_len);
				if ((seed_b) && (seed_b_len))
					hmac.update(seed_b, seed_b_len);
				hmac.done(digest_out1, hash_len);
            
				unsigned int copylen = outlen;
				if (copylen > hash_len)
					copylen = (unsigned int)hash_len;
            
				for (i = 0; i < copylen; i++) {
					output[idx++] = digest_out1[i];
					outlen--;
				}
            
				if (!outlen)
					break;
            
				tls_hmac hmac2(hash_len, (u8*)secret, secret_len);
				hmac2.update(digest_out0, hash_len);
				hmac2.done(digest_out0, hash_len);
			}
		}
	}
public:
	struct chiper_interface
	{
		TLS_CIPHER		cipher;
		tls_encoder*	(*encoder_create)();
		int				key_len;
		int				hash_len;
	};
	struct ECCCurveParameters
	{
		int  size;
		ECC_GROUP iana;
	};

	static int const ecc_count = 2;
	const ECCCurveParameters *ecc_list()
	{
		static ECCCurveParameters ecc[] = 
		{
			{
				32,
				ECC_secp256r1,
			},
			{
				48,
				ECC_secp384r1,
			}
		};
		return ecc;
	}
	static const int chiper_count = 9;
	const chiper_interface *chiper_list()
	{
		static chiper_interface c[] = {
			{TLS_AES_128_GCM_SHA256, create_encoder_aes, 16, 32},
			{TLS_AES_256_GCM_SHA384, create_encoder_aes, 32, 48},
			{TLS_CHACHA20_POLY1305_SHA256, create_encoder_chacha20, 32, 32},
			{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, create_encoder_aes, 16, 32},
			{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, create_encoder_aes, 32, 48},
			{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, create_encoder_chacha20, 32, 32},
			{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, create_encoder_aes, 16, 32},
			{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, create_encoder_aes, 32, 48},
			{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, create_encoder_chacha20, 32, 32},
		};
		return c;
	}
	

private:
	tlsbuf				pub_key, decode_buf;
	int					client_sequence_number,
						server_sequence_number;
	union 
	{
		struct {
			u8 secret[MAX_HASH_LEN], hs_secret[MAX_HASH_LEN], prk[MAX_HASH_LEN];
		} data13;
		struct {
			u8 client_rand[RAND_SIZE], server_rand[RAND_SIZE], master_key[48];
		} data12;
	};

	EccState	*pri_ecc_key[ecc_count];
	
	tls_hash	hash;
	int			cipher_index;
	tls_encoder *encoder;
	bool		encoding;
//	CLockData	lockdata;
public:
	tls_cipher()
	{
		encoder			= 0;
		memset(pri_ecc_key, 0, sizeof(pri_ecc_key));
		reset();
	}
	~tls_cipher()
	{
		reset();
	}

	void reset()
	{
	//	CLock lock(lockdata);
		pub_key.clear();
		memset(&data12, 0, max(sizeof(data12), sizeof(data13)));
		client_sequence_number = 0;
		server_sequence_number = 0;
		hash.reset();
		cipher_index= -1;
		encoding	= false;
		if(encoder)
			delete encoder;
		encoder = 0;
		for(int i = 0; i < ecc_count; i++)
			if(pri_ecc_key[i]){
				delete pri_ecc_key[i];
			}
		memset(pri_ecc_key, 0, sizeof(pri_ecc_key));
	}

	BYTE *create_client_rand()
	{
		for(int i = 0; i < sizeof(data12.client_rand); i++)
			data12.client_rand[i] = rand()&0xff;
		return data12.client_rand;
	}
	char *update_server_info(int cipher, const void *rand, bool tls_13)
	{
		cipher_index = -1;
		for(int i = 0; i < chiper_count; i++)
			if(chiper_list()[i].cipher == cipher)
				cipher_index = i;
		if(cipher_index == -1)
			return "没有对应的解码套件";
		encoder = chiper_list()[cipher_index].encoder_create();
		if(tls_13 == false)
			memcpy(data12.server_rand, rand, RAND_SIZE);
		return 0;

	}
	void get_hash(const char *out)
	{
	//	CLock lock(lockdata);
		hash.get_hash(out, get_hash_size());
	}
	void update_hash(const char *in, unsigned int len)
	{
	//	CLock lock(lockdata);
		hash.append(in, len);
	}
	int get_hash_size()
	{
		if(cipher_index == -1)
			return 32;
		return chiper_list()[cipher_index].hash_len;
	}

	const char *compute_pubkey(int ecc_index, tlsbuf &out)
	{
	//	CLock lock(lockdata);

		if(pri_ecc_key[ecc_index] == 0)
		{
			pri_ecc_key[ecc_index] = new EccState;
			if(ecc_init(pri_ecc_key[ecc_index], ecc_list()[ecc_index].size) != 0)
				return "初始化ecc key失败";
		}

		int size = MAX_PUBKEY_SIZE;
		out.check_size(MAX_PUBKEY_SIZE);

		out.size  += ecc_export_public_key(pri_ecc_key[ecc_index], (u8*)out.buf+out.size, MAX_PUBKEY_SIZE);

		return 0;
	}
	

private: 
	const char *compute_pre_key(ECC_GROUP ecc, const char *_server_key, int server_key_len, tlsbuf &premaster_key)
	{
		const ECCCurveParameters *cur_ecc = 0;
		int ecc_index;
		for(ecc_index = 0; ecc_index < ecc_count && cur_ecc == 0; ecc_index++)
			if(ecc == ecc_list()[ecc_index].iana)
				cur_ecc = &ecc_list()[ecc_index];
		ecc_index--;
		if(ecc_index >= ecc_count || cur_ecc == 0)
			return "没找到对应的ecc 参数";
		const char *ret = 0;
		if(ret = compute_pubkey(ecc_index, pub_key))
			return ret;

		premaster_key.set_size(ecc_list()[ecc_index].size);

		if(ecdh_shared_secret(pri_ecc_key[ecc_index], (u8*)_server_key, server_key_len, (u8*)premaster_key.buf) != 0)
			return "ecc计算pre master key失败";

		return 0;
	}
public:
	const char *tls12_compute_key(ECC_GROUP ecc, const char *_server_key, int server_key_len)
	{
		if(cipher_index == -1)
			return "compute_key error:没有对应的解码套件";
	//	CLock lock(lockdata);

		tlsbuf premaster_key;
		const char *ret = compute_pre_key(ecc, _server_key, server_key_len, premaster_key);
		if(ret)
			return ret;
		
		int key_len = chiper_list()[cipher_index].key_len;
		//----主密钥计算
		char master_secret_label[] = "master secret", key_expansion[] = "key expansion";
		_private_tls_prf((char*)data12.master_key, sizeof(data12.master_key), premaster_key.buf, premaster_key.size, master_secret_label, strlen(master_secret_label), (char*)data12.client_rand, RAND_SIZE, data12.server_rand, RAND_SIZE);
	
		unsigned char key[192];	//一个比较大的数组
		_private_tls_prf((char*)key, sizeof(key), (char*)data12.master_key, sizeof(data12.master_key), key_expansion, strlen(key_expansion), (char*)data12.server_rand, RAND_SIZE, data12.client_rand, RAND_SIZE);
		
		if(encoder->init(key, key+key_len, key+key_len*2, key+key_len*2 + encoder->iv_len(false), key_len, false) == false)
			return "初始化cipher失败";
		return 0;
	}

	const char *tls13_compute_key(ECC_GROUP ecc, const char *_server_key, int server_key_len, const char *finished_hash)
	{
		if(cipher_index == -1)
			return "compute_key error:没有对应的解码套件";
	//	CLock lock(lockdata);
		
		int key_len		= chiper_list()[cipher_index].key_len;
		int hash_len	= chiper_list()[cipher_index].hash_len;

		u8 hash[MAX_HASH_LEN];
		u8 earlysecret[MAX_HASH_LEN], salt[MAX_HASH_LEN];
		u8 local_keybuffer[MAX_KEY_SIZE], remote_keybuffer[MAX_KEY_SIZE];
		u8 local_ivbuffer[MAX_IV_SIZE], remote_ivbuffer[MAX_IV_SIZE];
		const char *server_key = ecc == ECC_NONE ? "s ap traffic" : "s hs traffic";
		const char *client_key = ecc == ECC_NONE ? "c ap traffic" : "c hs traffic";
		tls_hash hash2;
		hash2.get_hash((char*)hash, hash_len);
		memset(earlysecret, 0, sizeof(earlysecret));



		
		if(ecc == ECC_NONE)
		{
			_private_tls_hkdf_expand_label(salt, hash_len, (u8*)data13.prk, hash_len, "derived", 7, hash, hash_len);
			_private_tls_hkdf_extract(data13.prk, hash_len, salt, hash_len, earlysecret, hash_len);

			if(finished_hash)
				memcpy(hash, finished_hash, hash_len);
		}
		else
		{
			tlsbuf premaster_key;
			const char *ret = compute_pre_key(ecc, _server_key, server_key_len, premaster_key);
			if(ret)
				return ret;
			_private_tls_hkdf_extract(data13.prk, hash_len, NULL, 0, earlysecret, hash_len);
			_private_tls_hkdf_expand_label(salt, hash_len, data13.prk, hash_len, "derived", 7, hash, hash_len);
			_private_tls_hkdf_extract(data13.prk, hash_len, salt, hash_len, (u8*)premaster_key.buf, premaster_key.size);

			get_hash((char*)hash);
		}
		
		_private_tls_hkdf_expand_label(data13.hs_secret, hash_len, data13.prk, hash_len, client_key, strlen(client_key), hash, hash_len);
		
		_private_tls_hkdf_expand_label(local_keybuffer, key_len, data13.hs_secret, hash_len, "key", 3, NULL, 0);
		_private_tls_hkdf_expand_label(local_ivbuffer, encoder->iv_len(true), data13.hs_secret, hash_len, "iv", 2, NULL, 0);

		_private_tls_hkdf_expand_label(data13.secret, hash_len, data13.prk, hash_len, server_key, strlen(server_key), hash, hash_len);
		
		_private_tls_hkdf_expand_label(remote_keybuffer, key_len, data13.secret, hash_len, "key", 3, NULL, 0);
		_private_tls_hkdf_expand_label(remote_ivbuffer, encoder->iv_len(true), data13.secret, hash_len, "iv", 2, NULL, 0);

		
		if(encoder->init(local_keybuffer, remote_keybuffer, local_ivbuffer, remote_ivbuffer, key_len, true) == false)
			return "初始化cipher失败";

		return 0;
	}

	void compute_verify(tlsbuf &out, bool client_or_server, int verify_size, bool tls_13, int local_or_remote)
	{
		if(cipher_index == -1)
			return;
	//	CLock lock(lockdata);
		char hash[MAX_HASH_LEN];
		int  hash_len = chiper_list()[cipher_index].hash_len;	
		get_hash((char*)hash);
		
		if(tls_13 == false)
		{
			out.set_size(verify_size);
			_private_tls_prf(out.buf, out.size, (char*)data12.master_key, sizeof(data12.master_key), client_or_server == 0 ? "client finished" : "server finished", 15, hash, hash_len, NULL, 0);
		}
		else
		{
			u8 finished_key[MAX_HASH_LEN];
			if(local_or_remote)
				_private_tls_hkdf_expand_label(finished_key, hash_len, data13.secret, hash_len, "finished", 8, NULL, 0);
			else
				_private_tls_hkdf_expand_label(finished_key, hash_len, data13.hs_secret, hash_len, "finished", 8, NULL, 0);
			out.set_size(verify_size);
			tls_hmac hmac(chiper_list()[cipher_index].hash_len, finished_key, hash_len);
			hmac.update((u8*)hash, hash_len);
			hmac.done( (u8*)out.buf, out.buf_len);
		}
	}

	tlsbuf &get_pubkey()
	{
		return pub_key;
	}

	void encode(tlsbuf &sendbuf, const char *packet, int packet_size, bool keep_original, bool tls_13)
	{
	//	CLock lock(lockdata);
		if(!encoding || encoder == 0 || keep_original)
		{
			sendbuf.append(packet, packet_size);
			return ;
		}
		
		unsigned char aad[13];
		if(tls_13 == false)
		{
			*((uint64_t *)aad) = htonll(client_sequence_number++);//htonll(packet->context->local_sequence_number);
			aad[8]	= sendbuf.buf[0];
			aad[9]	= sendbuf.buf[1];
			aad[10] = sendbuf.buf[2];
			*((unsigned short *)(aad + 11)) = htons(packet_size);
		}
		else
		{
			aad[0] = CONTENT_APPLICATION_DATA;
			aad[1] = sendbuf.buf[1];
			aad[2] = sendbuf.buf[2];
			*((unsigned short *)(aad + 3)) = htons(encoder->compute_size(packet_size, 0, tls_13));		//-header_size
			*((uint64_t *)(aad+5)) = htonll(client_sequence_number++);
		}
		encoder->encode(sendbuf, packet, packet_size, aad, sizeof(aad), tls_13);
	}

	char *decode(tlsbuf_reader &inout, int packet_type, int version, bool tls_13)
	{
	//	CLock lock(lockdata);
		if(encoding == false || encoder == 0)
			return 0;
		unsigned char aad[13];
		if(tls_13 == false)
		{
			*((uint64_t *)aad) = htonll(server_sequence_number++);//htonll(context->remote_sequence_number);
			aad[8] = packet_type;
			aad[9] = htons(version)>>8;
			aad[10] = htons(version)&0xff;
			*((unsigned short *)(aad + 11)) = htons(encoder->compute_size(inout.buf_size, 1, tls_13));
		}
		else
		{
			aad[0] = CONTENT_APPLICATION_DATA;
			aad[1] = htons(version)>>8;
			aad[2] = htons(version)&0xff;
			*((unsigned short *)(aad + 3)) = htons(inout.buf_size);		//-header_size
			*((uint64_t *)(aad+5)) = htonll(server_sequence_number++);
		}
		char *ret = encoder->decode(inout, decode_buf, aad, sizeof(aad), tls_13);
		if(ret)
			return ret;
		inout.buf		= decode_buf.buf;
		inout.buf_size	= decode_buf.size;
		
		return 0;
	}

	bool verify_serverkey_exchange(int hash_type, const char *sign, int sign_size, const char *message, int msg_size)
	{
		return true;	//需要证书验证, SHA256(client_hello_random + server_hello_random + curve_info + public_key)
		if(encoder == 0)
			return false;
		//tlsbuf msg;
		//msg.append(tls12_client_rand, RAND_SIZE);
		//msg.append(tls12_server_rand, RAND_SIZE);
		//msg.append(message, msg_size);
		return true;
	}

	TLS_CIPHER get_chiper_type()
	{
		if(cipher_index  == -1)
			return TLS_NONE;
		return chiper_list()[cipher_index].cipher;
	}

	void set_encoding(bool v)
	{
		encoding = v;
	}
	bool get_encoding()
	{
		return encoding;
	}

	void reset_sequence_number()
	{
		client_sequence_number = 0;
		server_sequence_number = 0;
	}
};




class tls_client
{
	struct tlsstate
	{
		int content_type;
		int handshake_type;
	};
	const tlsstate *get_states_seq(bool tls_13)
	{
		static tlsstate s12[] = {{CONTENT_HANDSHAKE, MSG_SERVER_HELLO}, 
								{CONTENT_HANDSHAKE, MSG_CERTIFICATE}, 
								{CONTENT_HANDSHAKE, MSG_SERVER_KEY_EXCHANGE}, 
								{CONTENT_HANDSHAKE, MSG_SERVER_HELLO_DONE}, 
								{CONTENT_CHANGECIPHERSPEC, MSG_CHANGE_CIPHER_SPEC}, 
								{CONTENT_HANDSHAKE, MSG_FINISHED}}; 

		static tlsstate s13[] = {{CONTENT_HANDSHAKE, MSG_SERVER_HELLO}, 
								{CONTENT_CHANGECIPHERSPEC, MSG_CHANGE_CIPHER_SPEC}, 
								{CONTENT_HANDSHAKE, MSG_ENCRYPTED_EXTENSIONS}, 
								{CONTENT_HANDSHAKE, MSG_CERTIFICATE}, 
								{CONTENT_HANDSHAKE, MSG_CERTIFICATE_VERIFY}, 
								{CONTENT_HANDSHAKE, MSG_FINISHED}};
		return tls_13 ? s13 : s12;
	}
	int get_states_count(bool tls_13)
	{
		return tls_13 ? 6 : 4;	//tls12在hello done直接允许发送消息
	}
	int get_states_count()
	{
		return get_states_count(is_tls13(crypto.get_chiper_type()));
	}
	tls_cipher			crypto;
	SOCKET				s			= INVALID_SOCKET;
	int					state_index	= 0;

	tlsbuf				send_buf;
	tlsbuf				recv_buf;
	tlsbuf				recv_channel;
	tlsbuf				err_msg;
	int					recv_channel_readed	= 0;
	int					time_out			= 0x7fffffff;

	bool is_tls13(TLS_CIPHER cipher)
	{
		return cipher >= TLS_AES_128_GCM_SHA256 && cipher <= TLS_AES_128_CCM_8_SHA256;
	}

	const char *send_packet(int packet_type, int ver, tlsbuf &buf)
	{
		if(packet_type == CONTENT_HANDSHAKE && buf.size > 0)
			crypto.update_hash(buf.buf, buf.size);
		tlsbuf tmp_buf;
		tmp_buf.append((char)packet_type);
		tmp_buf.append((short)ver);
		int		body_size_index = tmp_buf.append_size(2);	//tls body size

		bool	keep_original	= packet_type == CONTENT_CHANGECIPHERSPEC || packet_type == CONTENT_ALERT;
		if(keep_original == false && crypto.get_encoding() && is_tls13(crypto.get_chiper_type()))
		{
			buf.append((char)packet_type);
			tmp_buf.buf[0] = CONTENT_APPLICATION_DATA;
		}

		crypto.encode(tmp_buf, buf.buf, buf.size, keep_original, is_tls13(crypto.get_chiper_type()));		//-----------加密代码

		*(u_short*)(tmp_buf.buf+body_size_index) = htons(tmp_buf.size - body_size_index - 2);
		if( ::send(s, tmp_buf.buf, tmp_buf.size, 0) != tmp_buf.size)
			return "发送数据失败";

		DumpData("发送数据:", tmp_buf.buf, tmp_buf.size);
		return 0;
	}
	
	const char *send_client_hello(SOCKET s, const char *host, tls_version version)
	{
		send_buf.clear();

		bool								hastls13		= false;

		send_buf.append((char)MSG_CLIENT_HELLO);
		int handshake_size_index = send_buf.append_size(3);		//tls handshake body size

		send_buf.append((short)0x303);
		send_buf.append(crypto.create_client_rand(), RAND_SIZE);
		send_buf.append((char)0);	//会话id，长度为0不提供
	
		int ciper_count_index	= send_buf.append_size(2);
		for(int i = 0; i < crypto.chiper_count; i++)
		{
			if(is_tls13(crypto.chiper_list()[i].cipher) && version != tls13)
				continue;
			send_buf.append(htons(crypto.chiper_list()[i].cipher));
			hastls13 |= is_tls13(crypto.chiper_list()[i].cipher);
		}
		*(unsigned short*)(send_buf.buf+ciper_count_index) = htons(send_buf.size - ciper_count_index-2);

		send_buf.append((char)1);	//不压缩
		send_buf.append((char)0);

		int ext_size_index = send_buf.append_size(2);
		send_buf.append(htons(EXT_SERVER_NAME));	//ext type 服务器名
		int host_len = strlen(host);
		send_buf.append(htons(host_len+5));	//host总长度
		send_buf.append(htons(host_len+3));	//第一个描述长度
		send_buf.append((char)0);	//第0个host也是唯一一个
		send_buf.append(htons(host_len));
		send_buf.append(host, host_len);
	

		send_buf.append(htons(EXT_SUPPORTED_GROUPS));	//ext type 椭圆曲线
		send_buf.append(htons(crypto.ecc_count*2+2));	//ext size	
		send_buf.append(htons(crypto.ecc_count*2));	//支持2个椭圆曲线
		for(int i = 0; i < crypto.ecc_count; i++)
			send_buf.append(htons(crypto.ecc_list()[i].iana));

		if(hastls13)
		{
			send_buf.append(htons(EXT_SUPPORTED_VERSION));
			send_buf.append(htons(3));
			send_buf.append((char)2);
			send_buf.append(htons(version));

			send_buf.append(htons(EXT_SIGNATURE_ALGORITHMS));	//
			send_buf.append(htons(24));	//
			send_buf.append(htons(22));	//
			send_buf.append(htons(0x0403));	//
			send_buf.append(htons(0x0503));	//
			send_buf.append(htons(0x0603));	//
			send_buf.append(htons(0x0804));	//
			send_buf.append(htons(0x0805));	//
			send_buf.append(htons(0x0806));	//
			send_buf.append(htons(0x0401));	//
			send_buf.append(htons(0x0501));	//
			send_buf.append(htons(0x0601));	//
			send_buf.append(htons(0x0203));	//
			send_buf.append(htons(0x0201));	//


			send_buf.append(htons(EXT_KEY_SHARE));	//ext type 椭圆曲线
			int share_size = send_buf.append_size(2);
			send_buf.append_size(2);
			for(int i = 0; i < crypto.ecc_count; i++)
			{
				auto &ecc = crypto.ecc_list()[i];
				send_buf.append(htons(ecc.iana));
				int share_size_sub = send_buf.append_size(2);
				const char *ret = crypto.compute_pubkey(i, send_buf);
				if(ret)
					return ret;
				*(u_short*)(send_buf.buf+share_size_sub) = htons(send_buf.size - share_size_sub - 2);
			}
			*(u_short*)(send_buf.buf+share_size) = htons(send_buf.size - share_size - 2);
			*(u_short*)(send_buf.buf+share_size+2) = htons(send_buf.size - share_size - 4);
		}
	

		*(u_short*)(send_buf.buf+ext_size_index) = htons(send_buf.size - ext_size_index - 2);
		send_buf.buf[handshake_size_index] = 0;
		*(u_short*)(send_buf.buf + handshake_size_index+1) = htons(send_buf.size - handshake_size_index - 3);

		return send_packet(CONTENT_HANDSHAKE, 0x303, send_buf);
	}

	const char *send_client_finish(SOCKET s)
	{
		tlsbuf verify;
		send_buf.clear();

		bool tls_13 = is_tls13(crypto.get_chiper_type());
		crypto.compute_verify(verify, 0, tls_13 == false ? 12 : crypto.get_hash_size(), tls_13, 0);

		send_buf.clear();
		send_buf.append((char)MSG_FINISHED);
		send_buf.append((char)0);
		send_buf.append(htons(verify.size));
		send_buf.append(verify.buf, verify.size);
		return send_packet(CONTENT_HANDSHAKE, 0x303, send_buf);
	}

	const char *send_client_exchange(SOCKET s)
	{
		send_buf.clear();
		tlsbuf &pubkey = crypto.get_pubkey();
		send_buf.append((char)MSG_CLIENT_KEY_EXCHANGE);
		send_buf.append((char)0);
		send_buf.append(htons(pubkey.size+1));
		send_buf.append((unsigned char)pubkey.size);	//tls body size
		send_buf.append(pubkey.buf, pubkey.size);
		return send_packet(CONTENT_HANDSHAKE, 0x303, send_buf);
	}

	const char *send_change_cipherspec(SOCKET s)
	{
		send_buf.clear();
		send_buf.append((char)1);
		return send_packet(CONTENT_CHANGECIPHERSPEC, 0x303, send_buf);
	}

	const char *on_server_hello(tlsbuf_reader &reader)
	{
		char server_rand[RAND_SIZE];

		int server_hello_size = ntohl(reader.read<char>()<<8 | reader.read<short>()<<16);
		int ver = ntohs(reader.read<short>());
		reader.read(server_rand, sizeof(server_rand));
		int session_len = reader.read<char>();
		reader.readed += session_len;
		TLS_CIPHER	cur_cipher	= (TLS_CIPHER)ntohs(reader.read<short>());	//选择的密码套件
		int			compress	= reader.read<char>();		//压缩方式

		const char *ret = crypto.update_server_info(cur_cipher, server_rand, is_tls13(cur_cipher));
		if(ret)
			return ret;

		if(reader.readed >= reader.buf_size)
			return 0;

		int ext_size	= ntohs(reader.read<short>());
		int ext_start	= reader.readed;
		int tls_ver		= 0;
		tlsbuf		pubkey;
		ECC_GROUP	eccgroup = ECC_NONE;
		while(reader.readed < ext_start + ext_size)
		{
			SSL_EXTENTION type = (SSL_EXTENTION)ntohs(reader.read<short>());
			if(type == EXT_SUPPORTED_VERSION)
			{
				reader.read<short>();
				tls_ver= ntohs(reader.read<short>());
			}
			else if(type == EXT_KEY_SHARE)
			{
				int size = ntohs(reader.read<short>());
				eccgroup = (ECC_GROUP)ntohs(reader.read<short>());
				if(size > 4)
				{
					pubkey.set_size(ntohs(reader.read<short>()));
					reader.read(pubkey.buf, pubkey.size);
				}
			}
		}
		if(tls_ver != 0)
		{
			if(tls_ver != 0x0304 || pubkey.size <= 0 || eccgroup == ECC_NONE)
				return "返回的椭圆参数不正确";
			const char *ret;
			if(ret = crypto.tls13_compute_key(eccgroup, pubkey.buf, pubkey.size, 0))
				return ret;
			crypto.set_encoding(true);
		}
		return 0;
	}

	const char *on_server_certificate(tlsbuf_reader &reader)
	{

		int server_certificates_size = ntohl(reader.read<char>()<<8 | reader.read<short>()<<16);
		int end_index2				 = reader.readed + server_certificates_size;
		//while(reader.readed < end_index2)
		//{
		//	int certificate_size = ntohl(reader.read<char>()<<8 | reader.read<short>()<<16);
			//int end_index3		 = reader.readed + certificate_size;
			//while(reader.readed < end_index3)
			//{
			//	int certificate_size2 = ntohl(reader.read<char>()<<8 | reader.read<short>()<<16);
			//	_asm nop
			//}
		//	reader.readed += certificate_size;
		//}
		return 0;
	}

	const char *on_server_key_exchange(tlsbuf_reader &reader)
	{

		int server_keyexchange_size = ntohl(reader.read<char>()<<8 | reader.read<short>()<<16);

		if(reader.read<char>() != 3)
			return "不支持的椭圆模式";
		ECC_GROUP eccgroup = (ECC_GROUP)ntohs(reader.read<short>());

		tlsbuf server_key, sign;
		server_key.append_size(reader.read<unsigned char>());
		reader.read(server_key.buf, server_key.size);

		const char *ret = crypto.tls12_compute_key(eccgroup, server_key.buf, server_key.size);
		if(ret)
			return ret;

		int msg_size	= reader.readed-4;
		int hash_type	= reader.read<unsigned char>();
		int sign_type	= reader.read<unsigned char>();
		int sign_size	= (int)ntohs(reader.read<short>());
		sign.append_size(sign_size);
		reader.read(sign.buf, sign.size);
		if(crypto.verify_serverkey_exchange(hash_type, sign.buf, sign.size, reader.buf+4, msg_size) == false)
			return "serverkeyexchange 签名验证失败";

		return 0;
	}
	const char *on_server_hello_done(tlsbuf_reader &reader)
	{
		const char *ret;
		if(ret = send_client_exchange(s))
			return ret;

		if(ret = send_change_cipherspec(s))
			return ret;
		crypto.set_encoding(true);
		if(ret = send_client_finish(s))
			return ret;
		
		return 0;
	}

	const char *verify_finished(tlsbuf_reader &reader)
	{
		int		server_finished_size = ntohl(reader.read<char>()<<8 | reader.read<short>()<<16);
		tlsbuf	verify;
		
		crypto.compute_verify(verify, 1, server_finished_size, is_tls13(crypto.get_chiper_type()), 1);

        if (memcmp(verify.buf, reader.buf+reader.readed, server_finished_size)) 
			return "on_server_finished 数据验证失败";
		return 0;
	}

	const char *on_server_finished(tlsbuf_reader &reader)
	{
		if(is_tls13(crypto.get_chiper_type()))
		{
			char finished_hash[MAX_HASH_LEN];
			crypto.get_hash(finished_hash);

			const char *ret = send_change_cipherspec(s);
			if(ret)
				return ret;
			if(ret = send_client_finish(s))
				return ret;
			crypto.reset_sequence_number();
			if(ret = crypto.tls13_compute_key(ECC_NONE, 0, 0, finished_hash))
				return ret;
		}
		return 0;
	}
	
	

	const char *on_packet(int packet_type, int version, tlsbuf_reader &reader)
	{
		const char *ret = 0;
		bool tls_13 = is_tls13(crypto.get_chiper_type());
		if(packet_type != CONTENT_CHANGECIPHERSPEC && packet_type != CONTENT_ALERT )
		{
			if(ret = crypto.decode(reader, packet_type, version, tls_13 )  )
				return ret;
			if(tls_13 && crypto.get_encoding() && reader.buf_size > 0)
			{
				packet_type = reader.buf[reader.buf_size-1];
				reader.buf_size--;
			}
		}

		while(reader.readed < reader.buf_size)
		{
			int seg_size	= packet_type == CONTENT_HANDSHAKE ? 1+3 + ntohl(reader.buf[reader.readed+1]<<8 | *(unsigned short*)(reader.buf + reader.readed+2)<<16) : reader.buf_size;
			tlsbuf_reader reader_sig(reader.buf+reader.readed, seg_size);

			const tlsstate *state_seq = get_states_seq(tls_13);
			if(state_index < get_states_count(tls_13) && packet_type != CONTENT_ALERT)
			{
				if(state_seq[state_index].content_type != packet_type || state_seq[state_index].handshake_type != reader_sig.buf[0])
					return "错误的状态";
				state_index++;
			}

			DumpData("接收数据:", reader_sig.buf, reader_sig.buf_size);
			if(packet_type == CONTENT_HANDSHAKE && reader_sig.buf_size > 0 && reader_sig.buf[0] != MSG_FINISHED)
				crypto.update_hash(reader_sig.buf, reader_sig.buf_size);
			if(packet_type == CONTENT_HANDSHAKE)
			{
				int handshake_type = reader_sig.read<unsigned char>();
				if(handshake_type == MSG_SERVER_HELLO)
					ret = on_server_hello(reader_sig);
				else if(handshake_type == MSG_CERTIFICATE)
					ret = on_server_certificate(reader_sig);
				else if(handshake_type == MSG_CERTIFICATE_VERIFY)
				{
				}
				else if(handshake_type == MSG_SERVER_KEY_EXCHANGE)
					ret = on_server_key_exchange(reader_sig);
				else if(handshake_type == MSG_SERVER_HELLO_DONE)
				{
					if(ret = on_server_hello_done(reader_sig))
						return ret;
				}
				else if(handshake_type == MSG_FINISHED)
				{
					if(ret = verify_finished(reader_sig))
						return ret;
					crypto.update_hash(reader_sig.buf, reader_sig.buf_size);
					if(ret = on_server_finished(reader_sig))
						return ret;
				}
				if(ret)
				{
					close();
					return ret;
				}
			}
			else if(packet_type == CONTENT_CHANGECIPHERSPEC)
			{
			}
			else if(packet_type == CONTENT_ALERT)
			{
				if(reader_sig.buf_size >= 2)
				{
					int level = reader_sig.read<unsigned char>();
					int code = reader_sig.read<unsigned char>();
					err_msg.set_size(256);
					sprintf(err_msg.buf, "tls alert,level:0x%x code:0x%x", level, code);
					return err_msg.buf;
				}
			}
			else if(packet_type == CONTENT_APPLICATION_DATA)
				recv_channel.append(reader.buf, reader.buf_size);
			reader.readed += seg_size;
		}
		return 0;
	}
	
	const char *process_recv()
	{
		if(s == INVALID_SOCKET)
			return 0;
		try
		{
			recv_buf.check_size(recv_buf.size+4096*4);
			int len = ::recv(s, recv_buf.buf+recv_buf.size, 4096*4, 0);
			if(len <= 0)
				throw "连接断开";
			recv_buf.size += len;

			int cur_index = 0;
			while(cur_index + 5 <= recv_buf.size)
			{
				int packet_size = ntohs(*(unsigned short*)(recv_buf.buf+cur_index+3));
				if(cur_index + 5 + packet_size > recv_buf.size)
					break;
				
				const char *ret = on_packet(*(BYTE*)(recv_buf.buf+cur_index), *(WORD*)(recv_buf.buf+cur_index+1), tlsbuf_reader(recv_buf.buf+cur_index+5, packet_size));
				if(ret)
					throw ret;

				cur_index += 5+packet_size;
			}
			memcpy(recv_buf.buf, recv_buf.buf+cur_index, recv_buf.size - cur_index);
			recv_buf.size -= cur_index;
			
		}catch(const char *err){
			close();
			return err;
		}
		return 0;
	}
	int read_channel(char *out, int size)
	{
		int movesize = min(size, recv_channel.size-recv_channel_readed);
		memcpy(out, recv_channel.buf+recv_channel_readed, movesize);
		recv_channel_readed += movesize;

		if(recv_channel_readed > recv_channel.size/4*3 && recv_channel.size > 1024*1024 || recv_channel_readed >= recv_channel.size)
		{
			memcpy(recv_channel.buf, recv_channel.buf+recv_channel_readed, recv_channel.size - recv_channel_readed);
			recv_channel.size -= recv_channel_readed;
			recv_channel_readed = 0;
		}
		return movesize;
	}
	int socket_signal(int wait_sec)
	{
		fd_set set;
		FD_ZERO(&set);
		FD_SET(s, &set);
		timeval tv;
		tv.tv_sec	= wait_sec;
		tv.tv_usec	= 0;
		int ret		= select(s+1, &set, 0, 0, &tv);
		if(ret > 0)
			return FD_ISSET(s, &set) ? 1 : 0;
		return ret == 0 ? 0 : -1;
	}
	int set_err(const char *msg, int ret)
	{
		int len = strlen(msg)+1;
		err_msg.set_size(len);
		memcpy(err_msg.buf, msg, len);
		return ret;
	}
public:
	tls_client()
	{
	}
	~tls_client()
	{
		close();
	}

	static void init_global()
	{
		static CLockData lockdata;
		CLock lock(lockdata);
		static bool inited = false;
		if(inited)
			return;
		aes_init_keygen_tables();
		inited = true;
	}

	void close()
	{
		state_index	= 0;
		recv_buf.clear();
		recv_channel.clear();
		recv_channel_readed = 0;
		crypto.reset();
		time_out		= 0x7fffffff;
		if(s != INVALID_SOCKET)
		{
			shutdown(s, SD_BOTH);
			closesocket(s);
		}
		s = INVALID_SOCKET;
	}

	void close_socket()
	{
		if(s != INVALID_SOCKET)
			closesocket(s);
	}

	const int open(const char *host, int port, unsigned int ip=0, tls_version version=tls12)
	{
		close();
		if(host == 0 || host[0] == 0)
			return set_err("host参数无效", -1);
		
		if(ip == 0)
		{
			hostent *h = gethostbyname(host);
			if(!h || h->h_length <= 0)
				return set_err("host没有对应的ip", -1);
			ip = *(DWORD*)h->h_addr_list[0];
		}
		s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if(s == INVALID_SOCKET)
			return set_err("创建socket失败", -1);
		SOCKADDR_IN addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_port	=	htons(port);
		addr.sin_addr.S_un.S_addr = ip;
		addr.sin_family = AF_INET;
		
		const char *ret = 0;
		try
		{
			if(connect(s, (sockaddr*)&addr, sizeof(addr)) != 0)
				throw "链接服务器失败";
			if((ret = send_client_hello(s, host, version)))
				throw ret;

			while(state_index < get_states_count())
			{
				if(ret = process_recv())
					throw ret;
			}
		}catch(const char *err){
			close();
			return set_err(err, -1);
		}

		return 0;
	}



	int send(char *buf, int size)
	{
		if(state_index < get_states_count())
			return 0;
		send_buf.clear();
		for(int i = 0; i < size;)
		{
			int send_size = min(size-i, 60000);
			send_buf.set_size(size);
			memcpy(send_buf.buf, buf+i, send_size);
			const char *ret = send_packet(CONTENT_APPLICATION_DATA, 0x303, send_buf);
			if(ret)
				return set_err(ret, 0);

			i += send_size;
		}
		return size;
	}


	int recv(char *out, int size)
	{
		DWORD dw = GetTickCount();
		if(state_index < get_states_count())
			return set_err("socket 未初始化", 0);
		while(1)
		{
			int signal = socket_signal(recv_channel.size <= recv_channel_readed ? 1 : 0);
			if(signal == -1)
				return set_err("socket select错误", 0);
			if(!signal && recv_channel.size > recv_channel_readed)
				break;

			if(signal == 0)
			{
				if(GetTickCount() - dw > (DWORD)time_out)
					return -1;
				continue;
			}
			const char *ret = process_recv();
			if(ret)
				return set_err(ret, 0);
		}
		return read_channel(out, size);
	}

	const char *errmsg()
	{
		return err_msg.buf;
	}

	bool online()
	{
		return state_index >= get_states_count();
	}

	void set_timeout(int v)
	{
		time_out = v;
	}
};
