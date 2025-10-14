#pragma once
#include "scanners/SignatureScanner.h"
#include "persistance/FileHashMem.h"

namespace lowlevel{
	class FileScanner {
	public:
		FileScanner(std::shared_ptr<FileHashMem> _fileHashMem);
		void scan(const char* path);
	private:
		std::shared_ptr<SignatureScanner> signatureScanner;
		std::shared_ptr<FileHashMem> fileHashMem;
	};
}