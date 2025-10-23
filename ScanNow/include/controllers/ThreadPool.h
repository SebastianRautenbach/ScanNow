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

    void WaitAll();

    template <class F, class ... Args>
    auto enqueue(F&& f, Args&&... args)
        -> std::future<typename std::invoke_result_t<F, Args...>>
    {
        using return_t = typename std::invoke_result_t<F, Args...>;
    
        auto task = std::make_shared<std::packaged_task<return_t()>>(
            [func = std::forward<F>(f), ... args = std::forward<Args>(args)]() mutable {
            return std::invoke(std::move(func), std::move(args)...);
        });
    
        std::future<return_t> result = task->get_future();
    
        {
            std::unique_lock<std::mutex> lock(m_mutex); // immediatly locks
            if (m_stop)
                throw std::runtime_error("enqueue on stopped ThreadPool");
    
            m_tasks.emplace([task]() { (*task)(); });
        } // unlocks mutex
    
        m_conVar.notify_one();
    
        return result;
    }

 




private:	
	uint32_t m_numThreads;
	std::queue<std::function<void()>> m_tasks;
	std::vector<std::thread> m_threads;
	std::mutex m_mutex;
	std::condition_variable m_conVar;
	bool m_stop;

};
