#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
//#define DEBUG_LOG(msg,...)
#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    pthread_mutex_t *mutex = thread_func_args->mutex;

    pthread_mutex_lock(mutex);
    thread_func_args->thread_complete_success = true;
    pthread_mutex_unlock(mutex);

    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
    struct thread_data *params;
    int rc;

    /* allocate memory for thread_data */
    params = malloc(sizeof(struct thread_data));
    if(params == NULL) {
        ERROR_LOG("malloc error\n");
        return 0;
    }

    /* setup mutex and wait arguments */
    params->mutex = mutex;
    params->thread_complete_success = false;
        
    /* create thread */
    rc = pthread_create(thread, NULL, threadfunc, params);
    if(rc != 0) {
        ERROR_LOG("pthread_create error rc %d\n", rc);
    }
        
    return true;
}

