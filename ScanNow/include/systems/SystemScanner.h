#pragma once
#include <memory>

namespace lowlevel {

	class DatabaseClient;
	class FileTraverser;
	class FileHashMem;


	class SystemScanner {
	public:
		// memory scan
		SystemScanner();
		void StartSystemScan();
		void Initialize();
		
		// file scan

	private:
		std::shared_ptr<DatabaseClient> m_dbClient;
		std::shared_ptr<FileTraverser> m_fileTraverser;
		std::shared_ptr<FileHashMem> m_fileHashMem;
	};
}