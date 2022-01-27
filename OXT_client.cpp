#include "OXT.hpp"
class OXT_client: 
    public OXT
{
    public:
    OXT_client();
    int stag();
}
OXT_client::OXT_client(){
    self.ddh = DiffieHellman()
    k_s = os.urandom(512)
    k_t = os.urandom(512)
    k_i = os.urandom(512)#for producing private key
    k_x = os.urandom(512)#for producing private key
    k_z = os.urandom(512)#for producing private key
    self.iv = os.urandom(16)
    self.client_key ={}
    self.client_key["k_x"]=k_x
    self.client_key["k_i"] = k_i
    self.client_key["k_s"]=k_s
    self.client_key["k_z"] = k_z
    self.client_key["k_t"] = k_t
}


