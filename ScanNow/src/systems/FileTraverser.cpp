#include "systems/FileTraverser.h"

lowlevel::FileTraverser::FileTraverser(std::shared_ptr<FileHashMem> fileHashMem)	
{
	m_fileScanner = std::make_shared<FileScanner>(fileHashMem);
}

void lowlevel::FileTraverser::scan(const char* path) {
	m_fileScanner->scan(path);
}