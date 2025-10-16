#include "systems/FileScanner.h"
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>

lowlevel::FileScanner::FileScanner(std::shared_ptr<FileHashMem> _fileHashMem)
    :m_fileHashMem(_fileHashMem)
{
	m_signatureScanner = std::make_shared<SignatureScanner>();
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
	
    if (m_signatureScanner->scan(original, m_fileHashMem)) {
        // bad file
        std::cout << "This is a bad file\n";
    }
    else {
        // good file
        std::cout << "This is a good file\n";
    }
}
