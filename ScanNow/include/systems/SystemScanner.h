#pragma once
#include "FileTraverser.h"

namespace lowlevel {
	class SystemScanner {
	public:
		// memory scan
		SystemScanner();
		void StartSystemScan();
		
		// file scan

	private:
		std::shared_ptr<DatabaseClient> m_dbClient;
		std::unique_ptr<FileTraverser> m_fileTraverser;
		std::shared_ptr<FileHashMem> m_fileHashMem;
	};
}