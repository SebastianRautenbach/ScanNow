#include "systems/SystemScanner.h"
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <crtdbg.h>
#include <assert.h>
#include <fltuser.h>
#include "systems/FileTraverser.h"
#include "controllers/DatabaseClient.h"



lowlevel::SystemScanner::SystemScanner()
{
	m_dbClient = std::make_shared<DatabaseClient>();
	m_fileHashMem = std::make_shared <FileHashMem>(m_dbClient);
	m_fileTraverser = std::make_shared < FileTraverser>(m_fileHashMem);
	
}

void lowlevel::SystemScanner::StartSystemScan()
{
	m_fileTraverser->scan("C:/Users/karat/Documents/glassfish7/");
}
