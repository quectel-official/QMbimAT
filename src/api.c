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

int mbim_SetSarEnable(int Value);                                  // Enable SAR
int mbim_GetSarEnable(int *pValue);                                // Get SAR Enable Status
int mbim_SetSarValue(const void *pValue, size_t size);             // Set SAR Band Power
int mbim_GetSarValue(unsigned char *pValue, unsigned short *size); // Get SAR Band Power
int mbim_SetDeviceReboot(int Value);
int mbim_get_efs_md5(int nv, unsigned char md5[16]);
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

int SetSarEnable(BOOL bEnable)
{
    int err = 0;

    pthread_mutex_lock(&mbim_mutex);
    err = mbim_SetSarEnable(bEnable);
    pthread_mutex_unlock(&mbim_mutex);
    mbim_debug("%s err=%d, bEnable=%d", __func__, err, bEnable);
    return err ? -1 : 0;
}

int GetSarEnable(BOOL *bEnable)
{
    int err = 0;
    int Value = 0;

    pthread_mutex_lock(&mbim_mutex);
    err = mbim_GetSarEnable(&Value);
    pthread_mutex_unlock(&mbim_mutex);
    if (!err)
        *bEnable = !!Value;
    mbim_debug("%s err=%d, bEnable=%d", __func__, err, *bEnable);
    return err ? -1 : 0;
}

void md5sum(const void *buf, size_t len, unsigned char md5sum[16]);

int GetFileMD5SUM(char *path, unsigned char md5[16])
{
    int ret = -1;
    struct stat st;
    char *data = NULL;
    int len;
    int fd;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        goto EXIT;

    if (fstat(fd, &st) != 0)
        goto EXIT;

    len = st.st_size;

    data = calloc(1, len);
    if (data == NULL)
        goto EXIT;

    if (read(fd, data, len) != len)
        goto EXIT;

    memset(md5, 0, 16);
    md5sum(data, len, md5);

    ret = 0;
EXIT:
    if (fd >= 0)
        close(fd);

    if (data)
        free(data);

    return ret;
}

int GetEFSMD5SUM(int nv, unsigned char md5[16])
{
    mbim_get_efs_md5(nv, md5);

    return 0;
}

int SetSarValue(const unsigned char *data, int len)
{
    int err = 0;

    pthread_mutex_lock(&mbim_mutex);
    err = mbim_SetSarValue(data, len);
    pthread_mutex_unlock(&mbim_mutex);
    mbim_debug("%s err=%d, data=%p, len=%d", __func__, err, data, len);
    return err ? -1 : 0;
}

int GetSarValue(unsigned char *sardata, unsigned short *count)
{
    int err = 0;

    pthread_mutex_lock(&mbim_mutex);
    err = mbim_GetSarValue(sardata, count);
    pthread_mutex_unlock(&mbim_mutex);
    mbim_debug("%s err=%d, data=%p, len=%d", __func__, err, sardata, *count);
    return err ? -1 : 0;
}

int SetDeviceReboot(int value)
{
    int err = 0;

    pthread_mutex_lock(&mbim_mutex);
    err = mbim_SetDeviceReboot(value);
    pthread_mutex_unlock(&mbim_mutex);
    mbim_debug("%s err=%d", __func__, err);
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

extern const char *dmidecode_query_lenovo_fcc_string(void);
int FccUnlock(void)
{
    int err = -1;
    const char *s;
    MBIM_RADIO_STATE_INFO_T RadioState;

    mbim_debug("%s", __func__);
    pthread_mutex_lock(&mbim_mutex);
    s = dmidecode_query_lenovo_fcc_string();
    if (!s)
    {
	    mbim_debug("fail to query lenovo fcc string!");
        goto out;
    }
    err = mbim_radio_state_query(&RadioState, 1);
    if (err)
    {
        goto out;
    }
    
    if (RadioState.HwRadioState == MBIMRadioOn)
    {
        goto out;
    }
    
    err = mbim_radio_state_set(MBIMRadioOn, 1);
    if (err)
    {
        goto out;
    }
    
    err= mbim_radio_state_query(&RadioState, 1);
out:
    pthread_mutex_unlock(&mbim_mutex);
    mbim_debug("%s err=%d", __func__, err);
    return err ? -1: 0;
}
