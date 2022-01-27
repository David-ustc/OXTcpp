#include <openssl/aes.h> 
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <string.h>
#define byte uint8_t

class Group{
    public:
    dh_st *Dfh;

    Group(){
    /* Generate the parameters to be used */
    this->Dfh = DH_new();

    DH_generate_parameters_ex(this->Dfh, 2048, DH_GENERATOR_2, NULL);

    }

    BIGNUM* genRandom(uint8_t* key, char* msg);
    BIGNUM* genPubKey(BIGNUM* privKey);
    BIGNUM* genPrivKey(uint8_t* key, char* msg);

};
uint8_t* prf_512(uint8_t* key, char* msg);
uint8_t* prf_256(uint8_t* key, char* msg);