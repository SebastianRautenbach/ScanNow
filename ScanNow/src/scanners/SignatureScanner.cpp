#include "scanners/SignatureScanner.h"
#include "persistance/FileHashMem.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

bool lowlevel::SignatureScanner::scan(const std::string& fileData, const std::shared_ptr<FileHashMem> hashMem)
{
    static thread_local std::array<unsigned char, picosha2::k_digest_size> hashBuffer;
    auto generatedHash = generateFileHash(fileData, hashBuffer);
    return compare(generatedHash, hashMem);
}

inline std::string lowlevel::SignatureScanner::generateFileHash(const std::string& fileData, std::array<unsigned char, picosha2::k_digest_size>& hashBuffer)
{    
    picosha2::hash256(fileData.begin(), fileData.end(), hashBuffer.begin(), hashBuffer.end());
    std::string result;
    result.reserve(picosha2::k_digest_size * 2);
    result = picosha2::bytes_to_hex_string(hashBuffer.begin(), hashBuffer.end());
    return result;
}

inline bool lowlevel::SignatureScanner::compare(const std::string& hash, const std::shared_ptr<FileHashMem> hashMem)
{
    return hashMem->getMaliciousHashes().count(hash);
}
