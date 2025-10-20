#include "systems/FileTraverser.h"
#include <thread>
#include <filesystem>
#include <iostream>

lowlevel::FileTraverser::FileTraverser(std::shared_ptr<FileHashMem> fileHashMem)	
{
	m_scanThreadPool = std::make_shared<ThreadPool>(m_numThread/2);
	m_fileThreadPool = std::make_shared<ThreadPool>(m_numThread / 2);
	m_fileScanner = std::make_shared<FileScanner>(fileHashMem);
}


void lowlevel::FileTraverser::scan(const char* path) {
	//for (uint32_t i = 0; i < m_filesQueue.size(); i++) {
	//	m_threadPool->enqueue(
	//		[this]() {m_fileScanner->scan(m_filesQueue.front().c_str());  });
	//}


	std::function<void(const char*)> ScanDir = [&](const char* path) {
		const std::filesystem::path  startPath(path);
		for (auto const& dirEntry : std::filesystem::directory_iterator{ startPath }) {
			if (dirEntry.is_directory()) {
				m_fileThreadPool->enqueue([this, dirEntry, ScanDir]() {
					ScanDir(dirEntry.path().string().c_str());
					});
			}
			else if(dirEntry.exists() && dirEntry.is_regular_file()) {
				m_scanThreadPool->enqueue([this, dirEntry]() {
					
					m_fileScanner->scan(dirEntry.path().string().c_str());

					});
			}
		}
		std::cout << m_filesQueue.size() << "\n";
	};

	ScanDir(path);
	


}