#include "controllers/ThreadPool.h"
#include <iostream>

ThreadPool::ThreadPool(uint32_t num_threads)
    : m_numThreads(num_threads), m_stop(false)
{
    for (uint32_t i = 0; i < m_numThreads; i++) {

        m_threads.emplace_back([this]() {
           

            while (true) {
                std::function<void()> task;

                {
                    std::unique_lock<std::mutex> lock(m_mutex);
                    m_conVar.wait(lock, [this]() {
                        return m_stop || !m_tasks.empty();
                        });

                    if (m_stop && m_tasks.empty()) {
                        return;
                    }

                    task = std::move(m_tasks.front());
                    m_tasks.pop();
                }

                task();
            }

        });
    }
}


ThreadPool::~ThreadPool()
{
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_stop = true;
    }

    m_conVar.notify_all();

    for (auto& thread : m_threads) {
        thread.join();
    }
}

void ThreadPool::WaitAll()
{
}
