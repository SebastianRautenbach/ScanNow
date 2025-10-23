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
    m_scanDir = [&](const std::string& path) {
        const std::filesystem::path startPath(path);

        try {
            for (auto const& dirEntry : std::filesystem::directory_iterator{ startPath }) {

                if (!dirEntry.exists()) continue;

                if (dirEntry.is_directory()) {
                    auto subPath = dirEntry.path().string();
                    m_fileThreadPool->enqueue([this, subPath]() {
                        m_scanDir(subPath);
                        });
                    //m_scanDir(subPath);
                }
                else if (dirEntry.is_regular_file()) {
                    auto filePath = dirEntry.path().string();
                    m_scanThreadPool->enqueue([this, filePath]() {
                    
                        if (m_fileScanner) {
                            m_fileScanner->scan(filePath.c_str());
                        }
                    
                        });
                    
                }
            }
        }
        catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "File Traverser error: " << e.what() << " (" << path << ")\n";
        }
        };

    m_scanDir(path);
}
