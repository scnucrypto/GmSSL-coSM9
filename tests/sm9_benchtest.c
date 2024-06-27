/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>
#include <gmssl/rand.h>
#include "bench.h"

// 一次性只能开启一个
#define COSIGN 0
#define CODEC 1
#define MAX_SIZE 10000

#if COSIGN
SM9_SIGN_CTX ctx;
SM9_COSIGN_KEYA keyA;
SM9_COSIGN_KEYB keyB;
SM9_SIGN_KEY key;
SM9_SIGN_MASTER_KEY mpk;
SM9_Z256_POINT ds;
uint8_t sig[1000] = {0};
size_t siglen = 0;
int j = 1;
uint8_t data[20] = {0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64};
uint8_t IDA[5] = {0x41, 0x6C, 0x69, 0x63, 0x65};
sm9_z256_t r1, s_t, h;
sm9_z256_fp12_t g, w1;
SM9_Z256_POINT S;
SM9_SIGNATURE signature;
uint8_t *sig_p = sig;

#define hex_ks		"000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4"

#define hex_ds \
	"A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820\n" \
	"78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3"

int init()
{
	sm9_z256_from_hex(mpk.ks, hex_ks); sm9_z256_twist_point_mul_generator(&(mpk.Ppubs), mpk.ks);
	sm9_cosign_master_key_extract_key(&mpk, (char *)IDA, sizeof(IDA), &keyA, &keyB);
	if (sm9_sign_master_key_extract_key(&mpk, (char *)IDA, sizeof(IDA), &key) < 0) goto err; ++j;
	sm9_z256_point_from_hex(&ds, hex_ds); if (!sm9_z256_point_equ(&(key.ds), &ds)) goto err; ++j;
	
	// 预计算
	sm9_z256_pairing(g, &(key.Ppubs), sm9_z256_generator());

	// 协同签名
    for (size_t i = 0; i < 100; i++)
    {
        sm9_cosign_A1(&keyA, g, r1, w1);
        sm9_cosign_B1(&keyB, g, data,  sizeof(data), w1, s_t, signature.h);
        sm9_cosign_A2(&keyA, r1, s_t, signature.h, &(signature.S));
    }

	if (sm9_signature_to_der(&signature, &sig_p, &siglen) != 1) {
		error_print();
		return -1;
	}
    format_bytes(stdout, 0, 0, "signature", sig, siglen);

	// sm9_sign_init(&ctx);
	// sm9_sign_update(&ctx, data, sizeof(data));
	// if (sm9_sign_finish(&ctx, &key, sig, &siglen) < 0) goto err; ++j;

	sm9_verify_init(&ctx);
	sm9_verify_update(&ctx, data, sizeof(data));
	if (sm9_verify_finish(&ctx, sig, siglen, &mpk, (char *)IDA, sizeof(IDA)) != 1) goto err; ++j;

	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

void run_genkey(int pid, size_t start, size_t end){
     for(size_t i=start;i<end;i++){
		sm9_cosign_master_key_extract_key(&mpk, (char *)IDA, sizeof(IDA), &keyA, &keyB);
     }
     exit(100+pid);
}

void run(int pid, size_t start, size_t end){
     for(size_t i=start;i<end;i++){
        sm9_cosign_A1(&keyA, g, r1, w1);
        sm9_cosign_B1(&keyB, g, data,  sizeof(data), w1, s_t, signature.h);
        sm9_cosign_A2(&keyA, r1, s_t, signature.h, &(signature.S));
     }
     exit(100+pid);
}
#endif

#if CODEC
SM9_ENC_MASTER_KEY msk;
SM9_ENC_KEY key;
SM9_Z256_TWIST_POINT de;
uint8_t out[1000] = {0};
size_t outlen = 0;
int j = 1;
uint8_t data[20] = {0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64};
uint8_t dec[20] = {0};
size_t declen = 20;
uint8_t IDB[3] = {0x42, 0x6F, 0x62};
SM9_Z256_POINT C1;
uint8_t c2[20];
uint8_t c3[SM3_HMAC_SIZE];
SM9_CODEC_KEYA keya;
SM9_CODEC_KEYB keyb;
sm9_z256_fp12_t w1;

#define hex_ke		"0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22"

#define hex_de \
	"94736ACD2C8C8796CC4785E938301A139A059D3537B6414140B2D31EECF41683\n" \
	"115BAE85F5D8BC6C3DBD9E5342979ACCCF3C2F4F28420B1CB4F8C0B59A19B158\n" \
	"7AA5E47570DA7600CD760A0CF7BEAF71C447F3844753FE74FA7BA92CA7D3B55F\n" \
	"27538A62E7F7BFB51DCE08704796D94C9D56734F119EA44732B50E31CDEB75C1"

int init()
{
	sm9_z256_from_hex(msk.ke, hex_ke);
	sm9_z256_point_mul_generator(&(msk.Ppube), msk.ke);

	if (sm9_enc_master_key_extract_key(&msk, (char *)IDB, sizeof(IDB), &key) < 0) goto err; ++j;
	if (sm9_codec_master_key_extract_key(&msk, (char *)IDB, sizeof(IDB), &keya, &keyb) < 0) goto err; ++j;

	sm9_z256_twist_point_from_hex(&de, hex_de); if (!sm9_z256_twist_point_equ(&(key.de), &de)) goto err; ++j;
	
	format_bytes(stdout, 0, 0, "plaintext", data, 20);

	if (sm9_do_encrypt(&msk, (char *)IDB, sizeof(IDB), data, sizeof(data), &C1, c2, c3) < 0) goto err; ++j;
	
#if 0
	// 普通解密
	if (sm9_do_decrypt(&key, (char *)IDB, sizeof(IDB), &C1, c2, sizeof(data), c3,  dec) < 0) goto err; ++j;
	if (memcmp(data, dec, sizeof(data)) != 0) goto err; ++j;
	format_bytes(stdout, 0, 0, "dec", dec, declen);
#endif

	// 协同解密
    if (sm9_do_codec_A1(&keya, &C1, w1) != 1) {
		error_print();
		return -1;
	}
    if (sm9_do_codec_B1(&keyb, (char *)IDB, sizeof(IDB), &C1, c2, sizeof(data), c3, w1, dec) != 1) {
		error_print();
		return -1;
	}
	format_bytes(stdout, 0, 0, "codec", dec, declen);
    if (memcmp(data, dec, sizeof(data)) != 0) goto err; ++j;
	printf("%s() ok\n", __FUNCTION__);
	return 1;
err:
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}

void run_genkey(int pid, size_t start, size_t end){
     for(size_t i=start;i<end;i++){
		if (sm9_codec_master_key_extract_key(&msk, (char *)IDB, sizeof(IDB), &keya, &keyb) < 0) printf("sm9_codec_master_key_extract_key error!\n");
     }
     exit(100+pid);
}

void run(int pid, size_t start, size_t end){
     for(size_t i=start;i<end;i++){
        if (sm9_do_codec_A1(&keya, &C1, w1) != 1) {
            error_print();
            return -1;
        }
        if (sm9_do_codec_B1(&keyb, (char *)IDB, sizeof(IDB), &C1, c2, sizeof(data), c3, w1, dec) != 1) {
            error_print();
            return -1;
        }
     }
     exit(100+pid);
}
#endif



int main(void) {
#if COSIGN
    init();
    bench_multiprocesses("SM9_cosign_genkey", 1000, 1, run_genkey);
    // bench_multiprocesses("SM9_co_sign", MAX_SIZE, 2, run_test);
    bench_multiprocesses("SM9_cosign_genkey", MAX_SIZE, 16, run_genkey);
    bench_multiprocesses("SM9_cosign_genkey", MAX_SIZE, 32, run_genkey);
    bench_multiprocesses("SM9_cosign_genkey", MAX_SIZE, 64, run_genkey);

    bench_multiprocesses("SM9_cosign", 1000, 1, run);
    // bench_multiprocesses("SM9_co_sign", MAX_SIZE, 2, run_test);
    bench_multiprocesses("SM9_cosign", MAX_SIZE, 16, run);
    bench_multiprocesses("SM9_cosign", MAX_SIZE, 32, run);
    bench_multiprocesses("SM9_cosign", MAX_SIZE, 64, run);
#endif

#if CODEC
    init();
    bench_multiprocesses("SM9_codec_genkey", 1000, 1, run_genkey);
    // bench_multiprocesses("SM9_co_sign", MAX_SIZE, 2, run_test);
    bench_multiprocesses("SM9_codec_genkey", MAX_SIZE, 16, run_genkey);
    bench_multiprocesses("SM9_codec_genkey", MAX_SIZE, 32, run_genkey);
    bench_multiprocesses("SM9_codec_genkey", MAX_SIZE, 64, run_genkey);

    bench_multiprocesses("SM9_codec", 1000, 1, run);
    // bench_multiprocesses("SM9_co_sign", MAX_SIZE, 2, run_test);
    bench_multiprocesses("SM9_codec", MAX_SIZE, 16, run);
    bench_multiprocesses("SM9_codec", MAX_SIZE, 32, run);
    bench_multiprocesses("SM9_codec", MAX_SIZE, 64, run);
#endif
}
