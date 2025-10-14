#pragma once
#include "FileScanner.h"
#include <thread>
#include <mutex>
#include <queue>



namespace lowlevel {
	class FileTraverser {
	public:
		FileTraverser(std::shared_ptr<FileHashMem> fileHashMem);
		void scan(const char* path);

	private:

		// worker threads


		std::shared_ptr<FileScanner> m_fileScanner;
		unsigned int m_numThread = std::thread::hardware_concurrency(); // for now
	};
}