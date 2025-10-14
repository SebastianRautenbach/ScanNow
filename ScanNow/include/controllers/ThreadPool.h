#pragma once
#include "models/ThreadSafeQueue.h"
#include <vector>
#include <thread>
#include <functional>

class ThreadPool {
public:
	explicit ThreadPool(uint32_t num_threads);
	~ThreadPool();

	bool push(std::function<void()> const& task);

private:	
	uint32_t m_numThreads;
	ThreadSafeQueue<std::function<void()>> m_tasks;
	std::vector<std::thread> m_threads;
	std::mutex m_mutex;
	std::condition_variable m_conVar;
	bool m_stop;

};
