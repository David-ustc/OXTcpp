#include <stdio.h>
#include <fstream>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <set>
#include <vector>
#include <map>

#include "crypto.cpp"
using namespace std;

class OXT
{
public:
    set<string> subwords;
    vector<string> keywords;
    map<string, vector<int>> dict;
    uint8_t k_s[16];
    uint8_t k_t[16];
    uint8_t k_i[16];
    uint8_t k_x[16];
    uint8_t k_z[16];

    OXT(char *keyword_file, int N)
    {

        this->preprocess(keyword_file, N);

        // key gen
        RAND_bytes(this->k_s, sizeof(k_s));
        RAND_bytes(this->k_t, sizeof(k_t));
        RAND_bytes(this->k_i, sizeof(k_i));
        RAND_bytes(this->k_x, sizeof(k_x));
        RAND_bytes(this->k_z, sizeof(k_z));

        //DB Setup
        this->DBSetup();
    }
    void preprocess(char *path, int N);
    void DBSetup();
    void TsetSetup();
};