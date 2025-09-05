#include <iostream>
#include "cryptonote_config.h"
#include "crypto/crypto_ops_builder/sha512.h"
#include "common/util.h" //beldex/common

int main()
{

   // tools::on_startup();

    std::string name = "saravanan";

    std::cout << CRYPTONOTE_NAME << std::endl;

    std::cout << crypto_hash_sha512_BYTES << std::endl;

    std::cout << name << std::endl;
}