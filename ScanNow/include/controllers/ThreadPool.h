#pragma once
#include "models/ThreadSafeQueue.h"
#include <vector>
#include <thread>
#include <functional>
#include <future>

class ThreadPool {
public:
	explicit ThreadPool(uint32_t num_threads);
	~ThreadPool();

	bool push(std::function<void()> const& task);

	template<class F, class... Args>
	inline auto Enqueue(F&& f, Args&&... args) -> std::future<decltype(f(args...))>
	{
		using return_type = decltype(f(args...));
		auto task = std::make_shared<std::packaged_task<return_type()>>(std::bind(std::forward<F>(f),
			std::forward<Args>(args)...));
		std::uni
	}

private:	
	uint32_t m_numThreads;
	ThreadSafeQueue<std::function<void()>> m_tasks;
	std::vector<std::thread> m_threads;
	std::mutex m_mutex;
	std::condition_variable m_conVar;
	bool m_stop;

};
