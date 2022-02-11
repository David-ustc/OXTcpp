#include <openssl/aes.h> 
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <string.h>
#include <iostream>
#define byte uint8_t

class Group{
    public:
    dh_st *Dfh;
	BIGNUM* p;
	BIGNUM* q;
	BIGNUM* g;
    Group(){
    /* Generate the parameters to be used */
		this->Dfh = DH_new();
		int rst = DH_generate_parameters_ex(Dfh, 1024, 2, NULL);
		DH_generate_key(this->Dfh);
		this->p = BN_dup(DH_get0_p(this->Dfh));
		this->g = BN_dup(DH_get0_g(this->Dfh));
		/*DH_generate_parameters_ex(Dfh, 4, DH_GENERATOR_2, NULL);
		DH_generate_key(Dfh);
		p = BN_dup(DH_get0_p(Dfh));
		g = BN_dup(DH_get0_g(Dfh));*/
		BN_dec2bn(&(this->q), "1403870480914070289696451458293996438139887772481");
		BN_dec2bn(&(this->g), "46277172657838521736982010709259150655651940460367394050907141021066563868957409091389998004058094482893541822318312908928337786268279527753269808811284019791227075265033622690754541844510895071227105785184008269865972998477535921067366288504155350389318378380800971350946080267698686922661978697262752896697");
		BN_dec2bn(&(this->p), "127658439009369975398290263538603156959260577330150356831118395565694927835969766105811900400495068876649383267866287449426149393411111640880808139129749364506990400060806613115125228066189438679261958067180275357369023000439351577876682523748194585842217411074407668064782195008617229133302221311224361277319");

    }

    BIGNUM* genRandom(uint8_t* key, char* msg);
    BIGNUM* genPubKey(BIGNUM* privKey);
    BIGNUM* genPrivKey(uint8_t* key, char* msg);
	BIGNUM* genSecret(BIGNUM* otherkey, BIGNUM* privkey);
};
void prf_256(uint8_t* key, char* msg, uint8_t* output);
void prf_512(uint8_t* key, char* msg, uint8_t* output);
int decrypt(unsigned char *inString, int inLen, unsigned char *passwd, unsigned char *deString);
int encrypt(unsigned char *inString, int inLen, unsigned char *aes_keybuf, unsigned char *enString);