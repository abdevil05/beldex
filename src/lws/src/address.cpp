#include <iostream>
#include "common/base58.h"
#include "cryptonote_basic/blobdatatype.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "serialization/binary_utils.h"

int main()
{
    std::string address = "bxcGCZJ8tpU5nszEbSpetMdbSePRo158kSBWxV9yUJfbR1rPyyZtAeTSKD5DXvn7G4c28qSWqkTfjNcPeJzGcPVQ26b35xzxE";
    uint64_t tag = 0;
    cryptonote::blobdata data ;
    bool check = tools::base58::decode_addr(address,tag,data);
    
    std::cout << "check : " << check << std::endl;
    std::cout << "address prifix : " << tag << std::endl;

    cryptonote::address_parse_info info;
    serialization::parse_binary(data, info.address);

    std::cout << "info.address.m_spend_public_key : " << info.address.m_spend_public_key << std::endl;
    std::cout << "info.address.m_view_public_key : " << info.address.m_view_public_key << std::endl;
    
    // std::cout << data << std::endl;
}