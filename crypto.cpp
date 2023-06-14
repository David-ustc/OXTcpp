#include "crypto.hpp"

#ifndef _ALGO_HMAC_H_
#define _ALGO_HMAC_H_
#endif

#define BLOCK_SIZE 16

uint8_t* prf_512(uint8_t* key, char* msg){
    const EVP_MD* engine = EVP_sha512();
    unsigned char* output = (unsigned char*)malloc(EVP_MAX_MD_SIZE);

    HMAC_CTX* ctx=HMAC_CTX_new();
    HMAC_CTX_reset(ctx);
    HMAC_Init_ex(ctx, key, strlen((char*)key), engine, NULL);
    HMAC_Update(ctx, (unsigned char*)msg, strlen(msg));        // input is OK; &input is WRONG !!!
    
    unsigned int len = 512;
    HMAC_Final(ctx, output, &len);
    HMAC_CTX_free(ctx);

    return output;
}
uint8_t* prf_256(uint8_t* key, char* msg){
    const EVP_MD* engine = EVP_sha512();
    unsigned char* output = (unsigned char*)malloc(EVP_MAX_MD_SIZE);

    HMAC_CTX* ctx=HMAC_CTX_new();
    HMAC_CTX_reset(ctx);
    HMAC_Init_ex(ctx, key, strlen((char*)key), engine, NULL);
    HMAC_Update(ctx, (unsigned char*)msg, strlen(msg));        // input is OK; &input is WRONG !!!

    unsigned int len = 256;
    HMAC_Final(ctx, output, &len);
    HMAC_CTX_free(ctx);

    return output;
}
int bytesToInt(uint8_t* bytes){
    // 位操作时 使用一个unsigned int变量来作为位容器。
    int addr = bytes[0] & 0xFF;
    addr |= ((bytes[1] << 8) & 0xFF00);
    addr |= ((bytes[2] << 16) & 0xFF0000);
    addr |= ((bytes[3] << 24) & 0xFF000000);
    return addr;
}
void intToByte(int i, uint8_t* bytes){
   size_t length = sizeof(int);
	// 初始化数组
    memset(bytes, 0, sizeof(uint8_t) * length);
    bytes[0] = (byte)(0xff & i);
    bytes[1] = (byte)((0xff00 & i) >> 8);
    bytes[2] = (byte)((0xff0000 & i) >> 16);
    bytes[3] = (byte)((0xff000000 & i) >> 24);
    return;
}
int fastPow(int a, int b,int p){
	int ans=1;
	while (a&&b)
	{
		if (b & 1) ans = ((ans*a) % p) % p;
		a = (a*a) % p;
		b >>= 1; //移位运算，右移一位
	}
	printf("%d",b);
	return ans;
}


BIGNUM* Group::genRandom(uint8_t* key, char* msg){
    BIGNUM* a;
    uint8_t* randomm = prf_512(key, msg);
    BN_hex2bn(&a, (char*)randomm);
    return a;
}
BIGNUM* Group::genPrivKey(uint8_t* key, char* msg){
    return genRandom(key, msg);
}
BIGNUM* Group::genPubKey(BIGNUM* privKey){
    BIGNUM* r;
    //BN_mod_exp(r, (this->Dfh)->params.g, privKey, this->Dfh->params.p, NULL);
    return r;
}	
