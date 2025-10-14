#include "systems/FileScanner.h"
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>

lowlevel::FileScanner::FileScanner(std::shared_ptr<FileHashMem> _fileHashMem)
    :fileHashMem(_fileHashMem)
{
	signatureScanner = std::make_shared<SignatureScanner>();
}

void lowlevel::FileScanner::scan(const char* path)
{
    std::ifstream file(path, std::ios_base::binary);
    static std::string original;

    if (file.is_open()) {
        std::stringstream buffer;
        buffer << file.rdbuf();
        original = buffer.str();       
    }
	
    if (signatureScanner->scan(original, fileHashMem)) {
        // bad file
    }
    else {
        // good file
    }
}
