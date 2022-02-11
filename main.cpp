#include "OXT.hpp"
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")

using namespace std;

int main(){
    int N = 200;
	string  path ="./data/trgm2.txt";
    OXT session = OXT((char *)path.c_str(), N);
	session.Search();
}