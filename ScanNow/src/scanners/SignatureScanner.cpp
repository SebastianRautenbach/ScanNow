#include "scanners/SignatureScanner.h"
#include "Persistance/FileHashMem.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include "picosha2.h"

bool lowlevel::SignatureScanner::scan(std::string& fileData, std::shared_ptr<FileHashMem> hashMem)
{

    auto generatedHash = generateFileHash(fileData);

    return compare(generatedHash, hashMem);
}

std::string lowlevel::SignatureScanner::generateFileHash(std::string& fileData)
{
    std::vector<unsigned char> hash(picosha2::k_digest_size);
    picosha2::hash256(fileData.begin(), fileData.end(), hash.begin(), hash.end());
    return picosha2::bytes_to_hex_string(hash.begin(), hash.end());
}

bool lowlevel::SignatureScanner::compare(std::string& hash, std::shared_ptr<FileHashMem> hashMem)
{
    return hashMem->temp_hashes.count(hash);    
}
