#include "crypto.hpp"
HMAC_CTX* ctx1=HMAC_CTX_new();
BN_CTX* ctx2 = BN_CTX_new();

void prf_512(uint8_t* key, char* msg, uint8_t* output){
    const EVP_MD* engine = EVP_sha512();
    HMAC_Init_ex(ctx1, key, strlen((char*)key), engine, NULL);
    HMAC_Update(ctx1, (uint8_t*)msg, strlen(msg));        // input is OK; &input is WRONG !!!
    
    unsigned int len = 512;
    HMAC_Final(ctx1, output, &len);
}

void prf_256(uint8_t* key, char* msg, uint8_t* output) {
	const EVP_MD* engine = EVP_sha256();
	HMAC_Init_ex(ctx1, key, strlen((char*)key), engine, NULL);
	HMAC_Update(ctx1, (uint8_t*)msg, strlen(msg));        // input is OK; &input is WRONG !!!

	unsigned int len = 256;
	HMAC_Final(ctx1, output, &len);
}

int encrypt(unsigned char *inString, int inLen, unsigned char *aes_keybuf, unsigned char *enString){
	std::cout << inString << std::endl;
	int i, j, len, nLoop, nRes;
	unsigned char buf[16];
	unsigned char buf2[16];
	AES_KEY aeskey;

	memset(aes_keybuf, 0x90, 32); int pwdLen = 32;
	if (pwdLen < 32) { len = pwdLen; }
	else { len = 32; }

	nLoop = inLen / 16; nRes = inLen % 16;

	AES_set_encrypt_key(aes_keybuf, 256, &aeskey);
	for (i = 0; i < nLoop; i++) {
		memset(buf, 0, 16);
		for (j = 0; j < 16; j++) buf[j] = inString[i * 16 + j];
		AES_encrypt(buf, buf2, &aeskey);
		for (j = 0; j < 16; j++) {
			enString[i * 16 + j] = buf2[j];
		}
	}
	if (nRes > 0) {
		memset(buf, 0, 16);
		for (j = 0; j < nRes; j++) buf[j] = inString[i * 16 + j];
		AES_encrypt(buf, buf2, &aeskey);
		for (j = 0; j < 16; j++) {
			enString[i * 16 + j] = buf2[j];
		}
	}
	enString[i * 16 + j] = 0;
	return 0;
}
int decrypt(unsigned char *inString, int inLen, unsigned char *passwd, unsigned char *deString){
	int i, j, len = 32, nLoop, nRes;
	unsigned char buf[16];
	unsigned char buf2[16];
	unsigned char aes_keybuf[32];
	AES_KEY aeskey;

	memset(aes_keybuf, 0x90, 32);
	for (i = 0; i < len; i++) aes_keybuf[i] = passwd[i];
	// 输入字节串分组成16字节的块		
	nLoop = inLen / 16; nRes = inLen % 16;
	AES_set_decrypt_key(aes_keybuf, 256, &aeskey);
	for (i = 0; i < nLoop; i++) {
		memset(buf, 0, 16);
		for (j = 0; j < 16; j++) buf[j] = inString[i * 16 + j];
		AES_decrypt(buf, buf2, &aeskey);
		for (j = 0; j < 16; j++) {
			deString[i * 16 + j] = buf2[j];
		}
	}
	if (nRes > 0) {
		memset(buf, 0, 16);
		for (j = 0; j < 16; j++) buf[j] = inString[i * 16 + j];
		AES_decrypt(buf, buf2, &aeskey);
		for (j = 0; j < 16; j++) {
			deString[i * 16 + j] = buf2[j];
		}
	}
	deString[i * 16 + nRes] = 0;
	return 0;
}
BIGNUM* Group::genRandom(uint8_t* key, char* msg){
    BIGNUM* a = BN_new();
	uint8_t* randomm = (uint8_t*)calloc(512 / 8, sizeof(uint8_t*));
	prf_512(key, msg, randomm);
    BN_bin2bn(randomm, 3, a);
	BIGNUM* ret = BN_new();
	BN_nnmod(ret, a, this->q, ctx2);
	free(randomm);
    return ret;
}
BIGNUM* Group::genPrivKey(uint8_t* key, char* msg){
    return genRandom(key, msg);
}
BIGNUM* Group::genPubKey(BIGNUM* privKey){
    BIGNUM* r = BN_new();
    if(!BN_mod_exp(r, this->g, privKey, this->p, ctx2))
		return NULL;
    return r;
}	
BIGNUM* Group::genSecret(BIGNUM* otherkey, BIGNUM* privkey) {
	BIGNUM* r = BN_new();
	if(!BN_mod_exp(r, otherkey, privkey, this->p, ctx2)) 
		return NULL;
	return r;
}