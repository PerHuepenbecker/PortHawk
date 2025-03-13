//
// Created by Per Hüpenbecker on 13.03.25.
//

#ifndef DOORSCAN_THREADSAFEQUEUE_H
#define DOORSCAN_THREADSAFEQUEUE_H

#include "../../Helpers/helpers.h"
#include <queue>

// Header only implementation of a simple thread safe queue. Decided for this mutex approach
// because of complexity reasons. Due to natural network delay the mutex is an acceptable option
// for the thread synchronization
template <typename T>
class ThreadSafeQueue {
    // STL queue as a base container for the thread safe queue
    std::queue<T> queue;
    // Access controlling mutex
    mutable std::mutex mutex;
    // Condition variable to notify waiting threads
    std::condition_variable cv;


public:
    // method to push a template item on the queue
    void push(T item) {
        // lock_guard for RAII
        std::lock_guard<std::mutex> lock(mutex);
        queue.push(item);
        cv.notify_one();
    }
    // method to try to pop an item from the queue
    bool try_pop(T& item) {
        std::lock_guard<std::mutex>lock(mutex);
        if(queue.empty()) {
            return false;
        }
        item = std::move(queue.front());
        queue.pop();
        return true;
    }

    // method using the cv to wait for an available item in the queue
    T pop() {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] {return !queue.empty();});
        T item = std::move(queue.front());
        queue.pop();
        return item;
    }

    // thread safe wrapper of the queue.empty() method
    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex);
        return queue.empty();
    }
};


#endif //DOORSCAN_THREADSAFEQUEUE_H
