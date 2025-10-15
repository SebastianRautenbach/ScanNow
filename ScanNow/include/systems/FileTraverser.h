#pragma once
#include "FileScanner.h"
#include <mutex>
#include <queue>
#include "controllers/ThreadPool.h"



namespace lowlevel {
	class FileTraverser {
	public:
		FileTraverser(std::shared_ptr<FileHashMem> fileHashMem);		
		void scan(const char* path);
	private:

		// worker threads

		std::shared_ptr<ThreadPool> m_threadPool;
		std::shared_ptr<FileScanner> m_fileScanner;
		unsigned int m_numThread = std::thread::hardware_concurrency(); // for now
	};
}