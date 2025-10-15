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

	//bool push(std::function<void()> const& task);

    template<class F, class... Args>
    auto Enqueue(F&& f, Args&&... args)
        -> std::future<typename std::invoke_result_t<F, Args...>>
    {
        using return_type = typename std::invoke_result_t<F, Args...>;

        auto task = std::make_shared<std::packaged_task<return_type()>>(
            [func = std::forward<F>(f), ... args = std::forward<Args>(args)]() mutable {
                return std::invoke(std::move(func), std::move(args)...);
            }
        );

        std::future<return_type> result = task->get_future();
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            if (m_stop)
                throw std::runtime_error("enqueue on stopped ThreadPool");

            m_tasks.emplace([task]() { (*task)(); });
        }
        m_conVar.notify_one();
        return result;
    }


private:	
	uint32_t m_numThreads;
	ThreadSafeQueue<std::function<void()>> m_tasks;
	std::vector<std::thread> m_threads;
	std::mutex m_mutex;
	std::condition_variable m_conVar;
	bool m_stop;

};
