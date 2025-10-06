#pragma once
#include "FileScanner.h"

namespace lowlevel {
	class FileTraverser {
	public:
		FileTraverser(std::shared_ptr<FileHashMem> fileHashMem);
		void scan(const char* path);

	private:
		std::shared_ptr<FileScanner> fileScanner;	
	};
}