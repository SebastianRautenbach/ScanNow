#include "controllers/ThreadPool.h"

ThreadPool::ThreadPool(uint32_t num_threads)
	: m_numThreads(num_threads), m_stop(false)
{
	for (uint32_t i = 0; i < num_threads; i++) {
		m_threads.emplace_back([this] {
			
			std::function<void()> task;
			while (1) {
				std::unique_lock<std::mutex>lock(m_mutex);
				
				m_conVar.wait(lock, [this] {
					
					return !m_tasks.isEmpty() || m_stop;
						
				});

				if (m_stop) {
					return;
				}

				task = std::move(m_tasks.front());
				m_tasks.pop();
				lock.unlock();
				task();

			}

			});
	}
}

ThreadPool::~ThreadPool()
{
}
