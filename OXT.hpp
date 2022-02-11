#include <stdio.h>
#include <fstream>
#include <iostream>
#include <stdlib.h>
#include <time.h>
#include <string>
#include <set>
#include <vector>
#include <map>
#include <openssl/rand.h>
#include "crypto.hpp"
#define ENCRYPTlen 16
using namespace std;
struct ey_tuple {
	string e;
	string y;
};
typedef ey_tuple EY;
class OXT
{
public:
	Group group;
    set<string> subwords;
    vector<string> keywords;
    map<string, vector<int>> dict;
	map<string, vector<EY>> T;
	set<string> Xset;
	vector<map<string, string> > TSet;
    uint8_t k_s[16];
    uint8_t k_t[16];
    uint8_t k_i[16];
    uint8_t k_x[16];
    uint8_t k_z[16];
	uint8_t iv[2];
    OXT(char *keyword_file, int N)
    {

        this->preprocess(keyword_file, N);

        // key gen
        RAND_bytes(this->k_s, sizeof(this->k_s));
        RAND_bytes(this->k_t, sizeof(this->k_t));
        RAND_bytes(this->k_i, sizeof(this->k_i));
        RAND_bytes(this->k_x, sizeof(this->k_x));
        RAND_bytes(this->k_z, sizeof(this->k_z));
		RAND_bytes(this->iv, sizeof(this->iv));
        //DB Setup
        this->DBSetup();
    }
    void preprocess(char *path, int N);
    void DBSetup();
    void TsetSetup();
	void Search();
	void Get_stag(string sub, uint8_t* stag);
	vector<EY> TSet_Retrieve(uint8_t* stag, string sub0);
};
uint8_t* BN2unchar(BIGNUM* num);
string BN2string(BIGNUM* num);
void scramble(vector<int> a, int n);