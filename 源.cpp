

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")


	class CLockData
	{
	public:
		CRITICAL_SECTION m_Criti;
		CLockData()
		{
			InitializeCriticalSection(&m_Criti);
		}
		~CLockData()
		{
			DeleteCriticalSection(&m_Criti);
		}
	};

	class CLock
	{
		CLockData *m_pData;
	public:
		CLock(CLockData &pData)
		{
			m_pData = &pData;
			EnterCriticalSection(&m_pData->m_Criti);
		}
		~CLock()
		{
			LeaveCriticalSection(&m_pData->m_Criti);
		}
	};


#include <crtdbg.h>
#include <stdint.h>
#include <stdio.h>
#include "tlsclient.cpp"

#define TEST_ENCODER
#ifdef TEST_ENCODER
#include "libtomcrypt.c"
#include <mmsystem.h>
#pragma comment(lib, "winmm.lib")
#endif
	
	
#ifdef TEST_ENCODER
void test_hash()
{
	u8 data1[123];
	u8 data2[1234];
	u8 result[128];
	for(int i = 0; i < sizeof(data1); i++)
		data1[i] = rand()&0xff;
	for(int i = 0; i < sizeof(data2); i++)
		data2[i] = rand()&0xff;

	DWORD dw = timeGetTime();
	sha256_ctx s1;
	for(int i = 0; i < 100000; i++)
	{
		sha256_init(&s1);
		sha256_update(&s1, data1, sizeof(data1));
		sha256_update(&s1, data2, sizeof(data2));
		sha256_final(&s1, result);
	}

	
	DWORD dw2 = timeGetTime();
	hash_state s2;
	for(int i = 0; i < 100000; i++)
	{
		sha256_init(&s2);
		sha256_process(&s2, data1, sizeof(data1));
		sha256_process(&s2, data2, sizeof(data2));
		sha256_done(&s2, result);
	}

	printf("test_hash 算法1耗时:%dms 算法2耗时:%dms\n", dw2-dw, GetTickCount() - dw2);
}

void test_ecc()
{
	u8 pubkey[256], secret[256];

	
	DWORD dw = timeGetTime();
	for(int i = 0; i < 100; i++)
	{
		EccState s1_1;
		ecc_init(&s1_1, 32);
		int pub_size = ecc_export_public_key(&s1_1, pubkey, sizeof(pubkey));
		ecdh_shared_secret(&s1_1, pubkey, pub_size, secret);
	}
	
	DWORD dw2 = timeGetTime();
	for(int i = 0; i < 100; i++)
	{
		ecc_key s2_1, s2_2;
		ecc_make_key_ex(0, find_prng("sprng"), &s2_1,  &ltc_ecc_sets[5]);
		ulong32 pub_size = sizeof(pubkey), secret_size = sizeof(secret);
		ecc_ansi_x963_export(&s2_1, pubkey, &pub_size);
		ecc_ansi_x963_import_ex(pubkey, pub_size, &s2_2, (ltc_ecc_set_type*)&ltc_ecc_sets[5]);
		ecc_shared_secret(&s2_1, &s2_2, secret, &secret_size);
	}
	
	printf("test_ecc 算法1耗时:%dms 算法2耗时:%dms\n", dw2-dw, GetTickCount() - dw2);
}

void test_gcm()
{
	u8 iv[12], aad[13], key[32], data1[1234], data2[123], result[2048], tag[32];
	for(int i = 0; i < sizeof(iv); i++)
		iv[i] = rand()&0xff;
	for(int i = 0; i < sizeof(aad); i++)
		aad[i] = rand()&0xff;
	for(int i = 0; i < sizeof(key); i++)
		key[i] = rand()&0xff;
	for(int i = 0; i < sizeof(data1); i++)
		data1[i] = rand()&0xff;
	for(int i = 0; i < sizeof(data2); i++)
		data2[i] = rand()&0xff;
	
	gcm_context s1;
	gcm_setkey(&s1, key, sizeof(key));
	gcm_state s2;
	int cipherID	= find_cipher("aes");
	gcm_init(&s2, cipherID, key, sizeof(key));


	DWORD dw = GetTickCount();
	for(int i = 0; i < 30000; i++)
	{
		gcm_start(&s1, DECRYPT, iv, sizeof(iv), aad, sizeof(aad));
        int res2 = gcm_update(&s1, sizeof(data1), data1, result);
        int res3 = gcm_update(&s1, sizeof(data2), data2, result);
		ulong32 tag_size = sizeof(tag);
		int res4 = gcm_finish(&s1, tag, tag_size);
	}


	DWORD dw2 = timeGetTime();
	for(int i = 0; i < 30000; i++)
	{
	
		gcm_reset(&s2);
        int res0 = gcm_add_iv(&s2, iv, sizeof(iv));
        int res1 = gcm_add_aad(&s2, aad, sizeof(aad));
        int res2 = gcm_process(&s2, result, sizeof(data1), data1, GCM_DECRYPT);
        int res3 = gcm_process(&s2, result, sizeof(data2), data2, GCM_DECRYPT);
		ulong32 tag_size = sizeof(tag);
		int res4 = gcm_done(&s2, tag, &tag_size);
	}
	printf("test_aes 算法1耗时:%dms 算法2耗时:%dms\n", dw2-dw, GetTickCount() - dw2);
}
#endif

void main()
{
#ifdef TEST_ENCODER
	timeBeginPeriod(1);
	aes_init_keygen_tables();
	ltc_mp = ltm_desc;
	register_prng(&sprng_desc);
	register_hash(&sha256_desc);
	register_hash(&sha1_desc);
	register_hash(&sha384_desc);
	register_hash(&sha512_desc);
	register_hash(&md5_desc);
	register_cipher(&aes_desc);
#endif

	WSADATA data;
	WSAStartup(MAKEWORD(2,2), &data);

	srand(GetTickCount());
	
#ifdef TEST_ENCODER
	test_gcm();
	test_hash();
	test_ecc();
#endif

	
	tls_client::init_global();
	
	{
		tls_client client;
		try
		{
			DWORD dw = GetTickCount();
			if(client.open("www.baidu.com", 443))
				throw client.errmsg();
			printf("耗时%d\n", GetTickCount()-dw);
	
			static char msg[] = "GET /fapi/v1/time HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: Keep-Alive\r\n\r\n";
			if(client.send(msg, strlen(msg)) != strlen(msg))
				throw client.errmsg();

			char buf[4096];
		//	while(1)
			{
				memset(buf, 0, sizeof(buf));
				int size = client.recv(buf, 4096);
				if(size > 0)
					printf(buf);
				else
					throw client.errmsg();
			}

			client.close();
			if(client.open("www.baidu.com", 443))
				throw client.errmsg();
	
			if(client.send(msg, strlen(msg)) != strlen(msg))
				throw client.errmsg();
			int size = client.recv(buf, 4096);
			if(size > 0)
				printf(buf);
			else
				throw client.errmsg();
		}catch(const char *err){
			printf("错误:  %s\n", err);
		}
	}
	
	getchar();
	_CrtDumpMemoryLeaks();
}