#include "systems/SystemScanner.h"

lowlevel::SystemScanner::SystemScanner()
{
	m_dbClient = std::make_shared<DatabaseClient>();
	m_fileHashMem = std::make_shared<FileHashMem>(m_dbClient);
	m_fileTraverser = std::make_unique<FileTraverser>(m_fileHashMem);
}

void lowlevel::SystemScanner::StartSystemScan()
{
	m_fileTraverser->scan("");
}
