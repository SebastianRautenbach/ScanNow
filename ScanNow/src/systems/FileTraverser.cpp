#include "systems/FileTraverser.h"
#include <chrono>
#include <thread>
#include <iostream>

lowlevel::FileTraverser::FileTraverser(std::shared_ptr<FileHashMem> fileHashMem)	
{
	m_threadPool = std::make_shared<ThreadPool>(m_numThread);
	m_fileScanner = std::make_shared<FileScanner>(fileHashMem);


	m_filesQueue.push("C:/Users/karat/Desktop/WIZMENGINES/WIZM_ENGINE v2.1/assimp-vc143-mtd.dll");
	m_filesQueue.push("C:/Users/karat/Desktop/WIZMENGINES/WIZM_ENGINE v2.1/fmod.dll");
	m_filesQueue.push("C:/Users/karat/Desktop/WIZMENGINES/WIZM_ENGINE v2.1/imgui.ini");
}

void lowlevel::FileTraverser::scan(const char* path) {

	//for (int i = 0; i < m_filesQueue.size(); i++) {
	//	m_threadPool->Enqueue([this, path]() {
	//		m_fileScanner->scan(m_filesQueue.front().c_str());
	//		});
	//}

	m_threadPool->Enqueue([]() {
		std::cout << "This is from Lambda Function \n";
		std::this_thread::sleep_for(std::chrono::milliseconds(2000));
		});
}