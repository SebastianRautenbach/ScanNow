#include "systems/FileTraverser.h"
#include <chrono>
#include <thread>
#include <iostream>

lowlevel::FileTraverser::FileTraverser(std::shared_ptr<FileHashMem> fileHashMem)	
{
	m_threadPool = std::make_shared<ThreadPool>(m_numThread);
	m_fileScanner = std::make_shared<FileScanner>(fileHashMem);
}


void lowlevel::FileTraverser::scan(const char* path) {
	for (uint32_t i = 0; i < m_filesQueue.size(); i++) {
		m_threadPool->enqueue(
			[this]() {m_fileScanner->scan(m_filesQueue.front().c_str());  });
	}
}