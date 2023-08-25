/*
    Copyright 2023 Quectel Wireless Solutions Co.,Ltd

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <stddef.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <poll.h>
#include <sys/time.h>
#include <endian.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <linux/un.h>
#include "mbim_protocol.h"
#include "mbim_ctx.h"

static int control_pipe[2] = {-1, -1};
static pthread_t mbim_read_tid = 0;
static int mbim_fd = -1;
static int mbim_verbose = 0;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_condattr_t mbim_command_attr;
static pthread_mutex_t mbim_command_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t mbim_command_cond = PTHREAD_COND_INITIALIZER;
static MBIM_MESSAGE_HEADER *mbim_pRequest;
static MBIM_MESSAGE_HEADER *mbim_pResponse;
static MBIM_INDICATE_STATUS_MSG_T *mbim_QmbeIndMsg /*just for UUID_MS_SARControl*/;
static uint32_t mbim_recv_buf[1024];
int use_mbim_proxy = 0;


const char *get_time(void)
{
    static char time_buf[50];
    struct timeval tv;
    time_t time;
    suseconds_t millitm;
    struct tm *ti;

    gettimeofday(&tv, NULL);

    time = tv.tv_sec;
    millitm = (tv.tv_usec + 500) / 1000;

    if (millitm == 1000)
    {
        ++time;
        millitm = 0;
    }

    ti = localtime(&time);
    sprintf(time_buf, "%02d-%02d_%02d:%02d:%02d:%03d", ti->tm_mon + 1, ti->tm_mday, ti->tm_hour, ti->tm_min, ti->tm_sec, (int)millitm);
    return time_buf;
}

static int pthread_cond_timeout_np(pthread_cond_t *cond, pthread_mutex_t *mutex, unsigned msecs)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    if (!msecs)
        msecs = -1;

    ts.tv_sec += (msecs / 1000);
    ts.tv_nsec += (((msecs % 1000) * 1000L) * 1000L);
    if ((unsigned long)ts.tv_nsec >= 1000000000UL)
    {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000UL;
    }

    return pthread_cond_timedwait(cond, mutex, &ts);
}

int wait_ind_state_report(uint32_t seconds)
{
    int retval = 0;

    if (mbim_QmbeIndMsg != NULL)
    {
        mbim_debug("info: mbim_QmedIndMsg aleary set");
    }
    else
    {
        pthread_mutex_lock(&mbim_command_mutex);
        retval = pthread_cond_timeout_np(&mbim_command_cond, &mbim_command_mutex, seconds * 1000);
        pthread_mutex_unlock(&mbim_command_mutex);
    }

    if (retval != 0)
        mbim_debug("seconds=%u, retval=%d", seconds, retval);
    return retval;
}

static void mbim_recv_command(MBIM_MESSAGE_HEADER *pResponse, unsigned size)
{
    (void)size;
    pthread_mutex_lock(&mbim_command_mutex);

    if (pResponse)
        mbim_dump(pResponse, mbim_verbose);

    if (pResponse == NULL)
    {
        pthread_cond_signal(&mbim_command_cond);
    }
    else if (mbim_pRequest && le32toh(mbim_pRequest->TransactionId) == le32toh(pResponse->TransactionId))
    {
        mbim_pResponse = mbim_alloc(le32toh(pResponse->MessageLength) + 1);
        if (mbim_pResponse)
            memcpy(mbim_pResponse, pResponse, le32toh(pResponse->MessageLength));
        pthread_cond_signal(&mbim_command_cond);
    }
    else if (le32toh(pResponse->MessageType) == MBIM_INDICATE_STATUS_MSG)
    {
        MBIM_INDICATE_STATUS_MSG_T *pIndMsg = (MBIM_INDICATE_STATUS_MSG_T *)pResponse;
    }

    pthread_mutex_unlock(&mbim_command_mutex);
}

int _mbim_send_command(MBIM_MESSAGE_HEADER *pRequest, MBIM_COMMAND_DONE_T **ppCmdDone, unsigned t_sec)
{
    int ret;
    unsigned msecs = t_sec * 1000;

    if (!pRequest)
        return -ENODEV;

    if (mbim_fd == -1)
        return -ENODEV;

    if (ppCmdDone)
        *ppCmdDone = NULL;

    pthread_mutex_lock(&mbim_command_mutex);
    if (mbim_QmbeIndMsg)
        mbim_free(mbim_QmbeIndMsg);
    mbim_dump(pRequest, mbim_verbose);

    mbim_pRequest = pRequest;
    mbim_pResponse = NULL;

    ret = write(mbim_fd, pRequest, le32toh(pRequest->MessageLength));

    if (ret > 0 && (uint32_t)ret == le32toh(pRequest->MessageLength))
    {
        ret = pthread_cond_timeout_np(&mbim_command_cond, &mbim_command_mutex, msecs);
        if (!ret)
        {
            if (mbim_pResponse && ppCmdDone)
            {
                *ppCmdDone = (MBIM_COMMAND_DONE_T *)mbim_pResponse;
            }
            else if (!mbim_pResponse && ppCmdDone)
            {
                ret = -ENODEV;
            }
        }
        else
        {
            mbim_debug("%s wait ret = %d", __func__, ret);
        }
    }
    else
    {
        mbim_debug("%s write ret = %d", __func__, ret);
    }

    mbim_pRequest = mbim_pResponse = NULL;

    pthread_mutex_unlock(&mbim_command_mutex);

    return ret;
}

int mbim_send_command(MBIM_MESSAGE_HEADER *pRequest, MBIM_COMMAND_DONE_T **ppCmdDone)
{
    return _mbim_send_command(pRequest, ppCmdDone, 30);
}

static void *mbim_read_thread(void *param)
{
    mbim_debug("%s is created", __func__);
    (void)param;

    while (mbim_fd > 0)
    {
        struct pollfd pollfds[] = {{mbim_fd, POLLIN, 0}, {control_pipe[0], POLLIN, 0}};
        int ne, ret, nevents = 2;

        ret = poll(pollfds, nevents, -1);

        if (ret <= 0)
        {
            mbim_debug("%s poll=%d, errno: %d (%s)", __func__, ret, errno, strerror(errno));
            break;
        }

        for (ne = 0; ne < nevents; ne++)
        {
            int fd = pollfds[ne].fd;
            short revents = pollfds[ne].revents;

            if (revents & (POLLERR | POLLHUP | POLLNVAL))
            {
                mbim_debug("%s poll err/hup/inval", __func__);
                mbim_debug("epoll fd = %d, events = 0x%04x", fd, revents);
                if (revents & (POLLERR | POLLHUP | POLLNVAL))
                    goto __quit;
            }

            if ((revents & POLLIN) == 0)
                continue;

            if (mbim_fd == fd)
            {
                ssize_t nreads;
                MBIM_MESSAGE_HEADER *pResponse = (MBIM_MESSAGE_HEADER *)mbim_recv_buf;

                nreads = read(fd, pResponse, sizeof(mbim_recv_buf));
                if (nreads <= 0)
                {
                    mbim_debug("%s read=%d errno: %d (%s)", __func__, (int)nreads, errno, strerror(errno));
                    break;
                }
                else if (nreads < pResponse->MessageLength)
                {
                    mbim_debug("error: %s read=%d MessageLength=%u", __func__, (int)nreads, pResponse->MessageLength);
                    break;
                }
                else if (nreads >= pResponse->MessageLength)
                {
                    while (nreads > 0)
                    {
                        mbim_debug("%s read=%d MessageLength=%u", __func__, (int)nreads, pResponse->MessageLength);

                        // coverity[tainted_data:FALSE]
                        mbim_recv_command(pResponse, pResponse->MessageLength);
                        nreads -= pResponse->MessageLength;
                        pResponse = (MBIM_MESSAGE_HEADER *)((char *)pResponse + pResponse->MessageLength);
                    }
                }
            }
            else if (control_pipe[0] == fd)
            {
                goto __quit;
            }
        }
    }

__quit:
    mbim_recv_command(NULL, 0);
    mbim_debug("%s exit", __func__);

    return NULL;
}

static int mbim_proxy_connect(void)
{
    int sock;
    struct sockaddr_un addr;
    socklen_t socklen;
    const char *n = "mbim-proxy";

    sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0)
        return -1;

    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path + 1, n, strlen(n));
    addr.sun_path[0] = '\0';
    socklen = offsetof(struct sockaddr_un, sun_path) + strlen(n) + 1;

    if (connect(sock, (struct sockaddr *)&addr, socklen) != 0)
    {
        mbim_debug("Fail to connect '%s', errno: %d (%s)", n, errno, strerror(errno));
        close(sock);
        sock = -1;
        goto EXIT;
    }

    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK) < 0)
    {
        mbim_debug("Fail to fcntl '%s', errno: %d (%s)", n, errno, strerror(errno));
        close(sock);
        sock = -1;
        goto EXIT;
    }

    mbim_debug("%s('%s') = %d", __func__, n, sock);

EXIT:
    return sock;
}

int mbim_ctx_init(int verbose)
{

    if (control_pipe[0] != -1)
        return 0;

    if (pipe(control_pipe))
        return -ENODEV;

    if (fcntl(control_pipe[0], F_SETFL, fcntl(control_pipe[0], F_GETFL) | O_NONBLOCK))
    {
        return -1;
    }
    if (fcntl(control_pipe[1], F_SETFL, fcntl(control_pipe[1], F_GETFL) | O_NONBLOCK))
    {
        return -1;
    }

    mbim_verbose = verbose;

    pthread_mutex_init(&mbim_command_mutex, NULL);
    pthread_condattr_init(&mbim_command_attr);
    pthread_condattr_setclock(&mbim_command_attr, CLOCK_MONOTONIC);
    pthread_cond_init(&mbim_command_cond, &mbim_command_attr);

    return 0;
}

void mbim_ctx_deinit(void)
{
    if (control_pipe[0] == -1)
        return;

    if (!use_mbim_proxy && mbim_fd)
    {
        mbim_CLOSE();
    }

    if (mbim_read_tid)
    {
        write(control_pipe[1], "q", 1);
        if (mbim_read_tid)
        {
            pthread_join(mbim_read_tid, NULL);
            mbim_read_tid = 0;
        }
    }
    mbim_fd_close(mbim_fd);
    mbim_fd_close(control_pipe[0]);
    mbim_fd_close(control_pipe[1]);
    pthread_cond_destroy(&mbim_command_cond);
}

int mbim_is_ready(const char *dev)
{
    char buff[128] = {};
    FILE *fp;

    if (!dev)
        return -ENODEV;

    if (control_pipe[0] == -1)
    {
        mbim_debug("%s pipe invaild", __func__);
        return -ENODEV;
    }

    if (mbim_fd != -1)
        return 0;

    fp = popen("ps -e |  grep mbim-proxy", "r");
    if (fp != NULL)
    {
        // coverity[check_return]
        fread(buff, 1, sizeof(buff) - 1, fp);
        pclose(fp);

        if (strstr(buff, "mbim-proxy"))
        {
            printf("use mbim-proxy\n\n");
            mbim_fd = mbim_proxy_connect();
            if (mbim_fd > 0)
            {
                if (pthread_create(&mbim_read_tid, NULL, mbim_read_thread, NULL))
                {
                    mbim_read_tid = 0;
                    return -ENODEV;
                }

                use_mbim_proxy = 1;
                if (mbim_proxy_configure(dev))
                {
                    write(control_pipe[1], "q", 1);
                    if (mbim_read_tid)
                    {
                        pthread_join(mbim_read_tid, NULL);
                        mbim_read_tid = 0;
                    }
                    mbim_fd_close(mbim_fd);
                    use_mbim_proxy = 0;
                }
            }
        }
    }

    if (mbim_fd < 0)
    {
        printf("use %s directly\n\n", dev);
        use_mbim_proxy = 0;

        mbim_fd = open(dev, O_RDWR);
        if (mbim_fd < 0)
        {
            perror(dev);
            return -ENODEV;
        }

        if (pthread_create(&mbim_read_tid, NULL, mbim_read_thread, NULL))
        {
            mbim_read_tid = 0;
            perror("pthread_create");
            return -ENODEV;
        }
        if (mbim_OPEN() < 0)
        {
            write(control_pipe[1], "q", 1);
            if (mbim_read_tid)
            {
                pthread_join(mbim_read_tid, NULL);
                mbim_read_tid = 0;
            }
            mbim_fd_close(mbim_fd);

            return -ENODEV;
        }
    }

    return 0;
}
