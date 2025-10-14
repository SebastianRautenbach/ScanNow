#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>

template <typename T>
class ThreadSafeQueue {
public:
	void push(T const& val) {
		std::lock_guard<std::mutex> lock(m_mutex);
		m_queue.push(val);
		m_conVar.notify_one();
	}

	T pop() {
		std::unique_lock<std::mutex> uLock(m_mutex);
		m_conVar.wait(uLock, [&] {return !m_queue.empty(); });
		T front = m_queue.front();
		m_queue.pop();
		return front;
	}

	T front() {
		std::unique_lock<std::mutex> uLock(m_mutex);
		m_conVar.wait(uLock, [&] {return !m_queue.empty(); });
		T front = m_queue.front();		
		return front;
	}

	bool isEmpty() {
		std::unique_lock<std::mutex> uLock(m_mutex);
		m_conVar.wait(uLock, [&] {return m_queue.empty(); });
		return true;
	}

private:
	std::queue<T> m_queue;
	std::condition_variable m_conVar;
	std::mutex m_mutex;
};
