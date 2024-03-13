#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

typedef unsigned int u32_t;
#define SYS_HZ 5 // In ms
static u32_t current_timeout_due_time;
static u32_t cached_now = 0;
static u32_t jiffies = 0;

static int TIMER_THREAD_PRIORITY = 99;
static pthread_t thread_id;
static pthread_mutex_t tid_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static cpu_set_t excl_cpuset;

static int ind_pipe[2] = {-1, -1};
int get_system_cpu_num()
{
    const char* path = "/sys/devices/system/cpu/online";
    int min, max = -1;
    int nr_cpus = 0;
    FILE* fp;

    if ((fp = fopen(path, "r")) != NULL) {
        fscanf(fp, "%d-%d", &min, &max); 
        if (max == -1)
            nr_cpus = 1;
        else
            nr_cpus = max + 1;
        fclose(fp);
    }

    return nr_cpus;
}

int set_current_task_attr(int cpu, int policy, int prio)
{
    cpu_set_t cpuset;
    struct sched_param param;
    int nr_cpu;

    nr_cpu = get_system_cpu_num();
    if (cpu >= nr_cpu) {
        printf("#BH Warn: cpuid[%d] is too large, should smaller than %d on this system!\n", cpu, nr_cpu);
        return -1;
    }
    
    if (cpu != -1) {
        /* CPU_ZERO(&cpuset);
        sched_getaffinity(0, sizeof(cpu_set_t), &cpuset);

        if(CPU_ISSET(cpu, &cpuset)) {
            goto SET_SCHE;
        }*/
        if (CPU_ISSET(cpu, &excl_cpuset)) {
            printf("#BH Warn: cpuid[%d] is in excluded CPU list!\n", cpu);
        }

        CPU_ZERO(&cpuset);
        CPU_SET(cpu, &cpuset);
        if (sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == -1) {
            printf("sched_setaffinity failed on cpu=%d with error[%d]='%s'\n",
                    cpu,
                    errno,
                    strerror(errno));
        }
    }

//SET_SCHE:
    if (policy != -1) {
        param.sched_priority = prio;
        if (sched_setscheduler(0, policy | SCHED_RESET_ON_FORK, &param) == -1) {
            printf("sched_setscheduler failed on policy=%d prio=%d with error[%d]='%s'\n",
                    policy,
                    prio,
                    errno,
                    strerror(errno));
        }
    }

    return 0;
}


static inline int get_timer_signum(void)
{
    return (SIGRTMIN + 1);
   // return SIGUSR2;
}
static void *timer_event_loop(void* arg __attribute__((unused)))
{
    int ret;
    sigset_t ss;
    siginfo_t si;
    struct sigaction action;
    int signum;

    if (getenv("BH_SET_THREAD_NAME") != NULL) {
        pthread_setname_np(pthread_self(), "PDCP-sys-timer");
    }

    char* cpu_env = getenv("PDCP_SYS_TIMER_CORE");
    int coreNum = 2;
    if (cpu_env != NULL) {
        coreNum = atoi(cpu_env);
    }
    printf("[Note][%s:%d]----------3-------------------\n", __func__, __LINE__);

    if (set_current_task_attr(coreNum, -1, 0) < 0) {
        printf("%s: Waring: sched_setaffinity failed.\n", "PDCP-sys-timer");
    }

    sigemptyset(&action.sa_mask);
    action.sa_sigaction = 0;
    action.sa_flags     = SA_SIGINFO;

    signum = get_timer_signum();
    if (sigaction(signum, &action, NULL) < 0) {
        printf("sigaction failed wtih error\n");
        return NULL;
    }
#ifndef CONFIG_VPP
    sigemptyset(&ss);
    sigaddset(&ss, signum);
    pthread_sigmask(SIG_BLOCK, &ss, NULL);
#endif
    /* Release thread which called init */
    pthread_mutex_unlock(&tid_mutex);

    for (;;) {
        do {
            ret = sigwaitinfo(&ss, &si);
        } while (ret < 0 && errno == EINTR);

        if (ret < 0 || si.si_signo != signum) {
            //printf("sigwaitinfo return failed\n");
            continue;
        }
		printf("[Note][%s:%d]---recv sig: %d\n", __func__, __LINE__, si.si_signo);
        jiffies ++;

       // sys_check_timeouts();
    }

    printf("Ending timer thread\n");

    return NULL;
}


int sys_timer_system_init(void)
{
    int policy = SCHED_RR;
    struct sched_param sched;
    struct sigevent ev;
    struct itimerspec it;
    pthread_attr_t attr;
    timer_t timerid;
    sigset_t ss;
    int signum;

    if (pipe(ind_pipe)) {
        printf("BH Waring: Indication Pipe open failed\n");
    }

    if (pthread_mutex_trylock(&tid_mutex)) {
        printf("Could not get timer creation mutex\n");
        return -1;
    }

    signum = get_timer_signum();
    sigemptyset(&ss);
    sigaddset(&ss, signum);
    sigprocmask(SIG_BLOCK, &ss, NULL);
    sched_getparam(0, &sched);

    sched.sched_priority = TIMER_THREAD_PRIORITY;

    pthread_attr_init(&attr);
    pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setschedpolicy(&attr, policy);
    pthread_attr_setschedparam(&attr, &sched);
    //pthread_attr_setstacksize(&attr,128*1024);
    if (pthread_create(&thread_id, &attr, timer_event_loop, NULL)) {
        printf("pthread_create filed\n");
        pthread_mutex_unlock(&tid_mutex);
        return -1;
    }

    //pthread_mutex_lock(&tid_mutex);
    pthread_mutex_unlock(&tid_mutex);

    ev.sigev_notify          = SIGEV_SIGNAL;
    ev.sigev_signo           = signum;
    ev.sigev_value.sival_ptr = NULL;
    printf("[Note][%s:%d]----------2-------------------\n", __func__, __LINE__);
    // while(1) sleep(1);

    if (timer_create(CLOCK_MONOTONIC, &ev, &timerid)) {
        printf("timer_create fail\n");
        return -1;
    }

    it.it_value.tv_sec = 1;
    it.it_value.tv_nsec = 0;
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_nsec = SYS_HZ*1000000;

    if (timer_settime(timerid, 0, &it, NULL)) {
        printf("timer_settime error\n");
        return -1;
    }
    printf("[Note][%s:%d]----------2-------------------\n", __func__, __LINE__);
         while(1) sleep(1);

    return 0;
}

#if 0
int main(int argc, char** argv)
{
	sys_timer_system_init();
	return 0;
}
#endif
