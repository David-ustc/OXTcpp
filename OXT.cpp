#include "OXT.hpp"
BN_CTX* ctx = BN_CTX_new();
void OXT::preprocess(char* path, int N){
    std::fstream fs;
    fs.open(path,std::ios::in|std::ios::out);
    fs.seekp(std::ios::beg);

    for(int index=0; index<N; index++){
        string s;
        getline(fs, s);
        this->keywords.push_back(s);
        for(int j=0; j<s.length()-1; j++){
            //TODO how to dissect
            string sub = s.substr(j, 2);
            cout<<sub;
            this->subwords.insert(sub);
            this->dict[sub].push_back(index); 
        }
		cout << endl;
    }
    fs.close();
}

void OXT::DBSetup(){
    for(set<string>::iterator i=this->subwords.begin();i!=this->subwords.end();i++){
        string sub = *i;
        vector<EY> list;
		uint8_t* k_e  = (uint8_t*)calloc(32, sizeof(uint8_t*));
		prf_256(this->k_s, (char *)sub.c_str(), k_e);
        for(int counter=0; counter < this->dict[sub].size(); counter++){
            int index = this->dict[sub][counter];
            string str = to_string(index);//!!!!!!!!!!!!!!!
            BIGNUM* xind = this->group.genRandom(this->k_i, (char*)str.c_str());

            str = to_string(counter);//!!!!!!!!!!!
            BIGNUM* z = this->group.genRandom(this->k_z, (char*)(sub + str).c_str());
            BIGNUM * z_inverse = BN_new();
			BN_mod_inverse(z_inverse, z, this->group.q, ctx);
            
			BIGNUM* y = BN_new();
			BN_mod_mul(y, xind, z_inverse, this->group.p, ctx);
			string y2 = BN2string(y); 
			//cout << y2 << endl;

			// encrypt e
			str = "0000"+to_string(index); //!!!!!!!!!!!
			string e = str.substr(str.length() - 3, 3);
			
			EY ey; ey.e = e; ey.y = y2;
			list.push_back(ey);
            //xtag
			BIGNUM* x = this->group.genRandom(this->k_x, (char*)(sub).c_str()); 
			BIGNUM* tmp = BN_new();
			BN_mod_exp(tmp, this->group.g, x, this->group.p, ctx);
			string xtag = BN2string(this->group.genSecret(tmp, xind)); 
			this->Xset.insert(xtag); 
        }
		this->T[sub] = list;
		free(k_e);
    }    

    this->TsetSetup();
}

void OXT::TsetSetup(){
	vector<map<string, string> > Tset(676);
	int i = 0;
	for (map<string, vector<EY> >::iterator iter = this->T.begin(); iter != this->T.end(); iter++, i++){
		uint8_t* stag = (uint8_t*)calloc(512 / 8, sizeof(uint8_t*));
		this->Get_stag(iter->first, stag);

		for (int j = 0; j < iter->second.size(); j++) {
			uint8_t* hash = (uint8_t*)calloc(512 / 8, sizeof(uint8_t*));
			prf_512(stag, (char*)to_string(j).c_str(), hash);
			string s = "1" + (iter->second[j].e) + (iter->second[j].y); //cout << s.length() << endl;
			if (j == iter->second.size() - 1) s[0] = '0';

			string label2(16, 'a');
			for (int k = 0; k < 16; k++)
				label2[k] = hash[k];

			string value = s;
			for (int k = 0 ; k < 512/8 - 16; k++)
				value[k] = s[k] ^ hash[k+16];
			for (int k = 512/8 - 16; k < s.length(); k++)
				value[k] = s[k];
			unsigned int b = (hash[0] + hash[1]) % Tset.size();
			Tset[b][label2] = value;
			free(hash);
		}
		
		free(stag);
	}
	this->TSet = Tset;
    return;
}
void OXT::Search(){
	string affix = "Baikal$";
	vector<string> substrings;
	affix.replace(affix.find('$'), 1, "");
	for (int j = 0; j < affix.length() - 1; j++) {
		//TODO how to dissect
		string sub = affix.substr(j, 2);
		substrings.push_back(sub);
	}
	int n = substrings.size();

	//stag and xtoken
	uint8_t* stag = (uint8_t*)calloc(512 / 8, sizeof(uint8_t*));
	this->Get_stag(substrings[0], stag);
	vector<EY> list = this->TSet_Retrieve(stag, substrings[0]);
	vector< vector<BIGNUM*> > xtoken(list.size(), vector<BIGNUM*>(n+1));
	for (int c = 0; c < list.size(); c++ ) {
		for (int i = 2; i <= n; i++) {
			BIGNUM* z = this->group.genRandom(this->k_z, (char*)((substrings[0] + to_string(c)).c_str()) );
			BIGNUM* xtrap = this->group.genRandom(this->k_x, (char*)(substrings[i-1]).c_str());
			BIGNUM* tmp = this->group.genPubKey(xtrap);
			xtoken[c][i] = this->group.genSecret(tmp, z);
		}
	}
	//one by one quickly
	for (int c = 0; c < list.size(); c++) {
		string y = list[c].y;
		BIGNUM* y2 = BN_new();
		BN_dec2bn(&y2, y.c_str());

		int i = 0;
		for (i = 2; i <= n; i++) {
			BIGNUM* xtag = this->group.genSecret(xtoken[c][i], y2);
			string xtag2 = BN2string(xtag);
			if (this->Xset.count(xtag2)!=1)
				break;
		}
		if (i > n) {
			//decrypt e to get the index of w
			cout << list[c].e << endl;
		}
	}

}
void OXT::Get_stag(string sub, uint8_t* stag){
	prf_512(this->k_t, (char*)sub.c_str(), stag);
}
vector<EY> OXT:: TSet_Retrieve(uint8_t* stag, string sub0){
	vector<EY> list;
	string beta = "1";
	int i = 0;
	while(beta=="1") {
		uint8_t* hash = (uint8_t*)calloc(512 / 8, sizeof(uint8_t*));
		prf_512(stag, (char*)to_string(i).c_str(), hash);
		i++;

		string label2 (16, 'a');
		for (int k = 0; k < 16; k++)
			label2[k] = hash[k];
		unsigned int b = (hash[0] + hash[1]) % this->TSet.size();
		string xor_value = this->TSet[b][label2];

		string value = xor_value;
		for (int k = 0; k < 512 / 8 - 16; k++)
			value[k] = xor_value[k] ^ hash[k + 16];
		for (int k = 512 / 8 - 16; k < value.length(); k++)
			value[k] = xor_value[k];

		beta = value[0];
		string e = value.substr(1, 3);
		string y = value.substr(4, value.length() - 4);
		cout << " "<<value << endl;
		EY ey; ey.e = e; ey.y = y;
		list.push_back(ey);

		free(hash);
	}
	return list;
}

uint8_t* BN2unchar(BIGNUM* num) {
	uint8_t* s = (uint8_t*)calloc(BN_num_bytes(num), sizeof(uint8_t));
	BN_bn2bin(num, s);
	return s;
}
string BN2string(BIGNUM* num) {
	/*uint8_t* s = (uint8_t*)calloc(BN_num_bytes(num), sizeof(uint8_t));
	BN_bn2bin(num, s);
	string str = (char*)s;
	printf("%x", s);
	free(s);
	return str;*/
	char* s = BN_bn2dec(num);
	string str = s;
	return str;
}
void scramble(vector<int> a, int n)
{
	for (int i = 0; i < n; i++) {
		a.push_back(i);
	}
	int index, tmp, i;
	srand(time(NULL));
	for (i = 0; i < n; i++)
	{
		index = rand() % (n - i) + i;
		if (index != i)
		{
			tmp = a[i];
			a[i] = a[index];
			a[index] = tmp;
		}
	}
}