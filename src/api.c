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
#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mbim_protocol.h"
#include "mbim_ctx.h"
#include "api.h"

int mbim_send_at_command(const char *atc_req, char **pp_atc_rsp);

static pthread_mutex_t mbim_mutex = PTHREAD_MUTEX_INITIALIZER;
static char mbim_dev[32];
BOOL mbim_tool_debug = 0;

FILE *log_fp = NULL;
int Init(const char *dev_path)
{
    int err = 0;

    if (mbim_tool_debug)
        log_fp = stdout;

    strncpy(mbim_dev, dev_path, sizeof(mbim_dev) - 1);
    pthread_mutex_lock(&mbim_mutex);
    err = mbim_ctx_init(mbim_tool_debug);
    pthread_mutex_unlock(&mbim_mutex);

    return err ? -1 : 0;
}

void UnInit(void)
{
    pthread_mutex_lock(&mbim_mutex);
    mbim_ctx_deinit();
    pthread_mutex_unlock(&mbim_mutex);
    mbim_debug("%s", __func__);
}

int GetIsMbimReady(BOOL *bValue)
{
    int err = 0;

    pthread_mutex_lock(&mbim_mutex);
    err = mbim_is_ready(mbim_dev);
    pthread_mutex_unlock(&mbim_mutex);
    if (!err)
        *bValue = 1;

    return err ? -1 : 0;
}

int send_at_command(char *at_req, char **at_resp)
{
    int err = 0;

    pthread_mutex_lock(&mbim_mutex);
    err = mbim_send_at_command(at_req, at_resp);
    pthread_mutex_unlock(&mbim_mutex);
    mbim_debug("%s err=%d", __func__, err);
    return err ? -1 : 0;
}
