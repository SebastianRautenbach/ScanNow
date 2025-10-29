#pragma once
#include "scanners/SignatureScanner.h"
#include "persistance/FileHashMem.h"

namespace lowlevel{
	class FileScanner {
	public:
		FileScanner(std::shared_ptr<FileHashMem> _fileHashMem);
		void scan(const char* path);
		~FileScanner() {
		}
	private:
		std::shared_ptr<SignatureScanner> m_signatureScanner;
		std::shared_ptr<FileHashMem> m_fileHashMem;
	};
}