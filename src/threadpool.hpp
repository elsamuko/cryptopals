#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <functional>
#include <atomic>
#include <iostream>

class Threadpool {
    public:
        using Job = std::function<void()>;
        Threadpool( size_t threads = 0 ) {

            if( !threads ) {
                threads = std::thread::hardware_concurrency();
            }

            while( threads-- ) {
                workers.emplace_back( [this] {
                    for( ;; ) {
                        this->work();

                        if( stop && !this->count ) {
                            break;
                        }
                    }
                } );
            }
        }

        void waitForJobs() {
            while( this->count ) {
                std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
            }
        }

        ~Threadpool() {
            stop = true;

            for( auto& worker : workers ) {
                worker.join();
            }
        }

        void add( const Job& job ) {
            std::unique_lock<std::mutex> lock( m );
            jobs.emplace( job );
            count++;
        }

        void work() {
            Job job;
            {
                std::unique_lock<std::mutex> lock( m );

                if( !jobs.empty() ) {
                    job = jobs.front();
                    jobs.pop();
                }
            }

            if( job ) {
                job();
                count--;
            }
        }

    private:
        std::atomic_bool stop = false;
        std::vector<std::thread> workers;
        std::mutex m;
        std::atomic_int count = 0;
        std::queue<std::function<void()>> jobs;
};
