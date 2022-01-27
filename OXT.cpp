#include "OXT.hpp"


void OXT::preprocess(char* path, int N){
    std::fstream fs;
    fs.open(path,std::ios::in|std::ios::out);
    fs.seekp(std::ios::beg);

    for(int index=0; index<N; index++){
        string s;
        getline(fs, s);
        this->keywords.push_back(s);
        for(int j=0; j<s.length(); j++){
            //TODO how to dissect
            string sub = s.substr(j, 1);
            
            this->subwords.insert(s);
            this->dict[sub].push_back(index); 
        }
    }
    fs.close();
}

void OXT::DBSetup(){
    Group group = Group();
    for(set<string>::iterator i=this->subwords.begin();i!=this->subwords.end();i++){
        string sub = *i;
        cout<<"db "<<sub<<endl;
        uint8_t* k_e = prf_256(this->k_s, (char *)sub.c_str());
        for(int counter=0; counter<this->dict[sub].size(); counter++){
            int index = this->dict[sub][counter];
            string str = to_string(index);
            BIGNUM* xind = group.genRandom(this->k_i, (char*)str.c_str());
            str = to_string(counter);
            BIGNUM* z = group.genRandom(this->k_z, (char*)(sub + str).c_str());
            BIGNUM * z_inverse;
            //BN_mod_inverse(z_inverse, z, (group.Dfh)->p, NULL);
            
            

            //xtag
        }
    }    

    //TsetSetup();
}



void OXT::TsetSetup(){
    return;
}
void Search(){

}
void Get_stag(){

}
void TSet_Retrieve(){

}
