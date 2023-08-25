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
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <dlfcn.h>

#include "version.h"
#include "api.h"

static void debug_tool_usage()
{
    printf("./qmbimat -d <mbim device> -a <at command>\n");
}

int debug_tool(int argc, char *argv[])
{
    int ret = -1;
    int opt;
    char *dev = NULL;
    BOOL bValue = 0;
    int err;
    char at_req[128] = {};

    struct option longopts[] = {
        {"version", 0, NULL, 'V'},
        {"debug", 0, NULL, 'D'},
        {},
    };

    if (argc <= 1)
    {
        debug_tool_usage();
        return 0;
    }

    while (-1 != (opt = getopt_long(argc, argv, "a:d:vh", longopts, NULL)))
    {
        switch (opt)
        {
        case 'd':
            if (dev != NULL)
            {
                free(dev);
                dev = NULL;
            }

            if (optarg != NULL)
                dev = strdup(optarg);
            break;
        case 'a':
            if (optarg && strlen(optarg) >= sizeof(at_req))
            {
                printf("at command is too long\n");
                goto EXIT;
            }

            if (optarg != NULL)
            {
                strcpy(at_req, optarg);
            }
            else
            {
                debug_tool_usage();
                goto EXIT;
            }
            break;
        case 'D':
            mbim_tool_debug = 1;
            break;
        case 'V':
            printf("%s\n", VERSION);
            ret = 0;
            goto EXIT;
        case 'h':
        default:
            debug_tool_usage();
            ret = 0;
            goto EXIT;
        }
    }

    if (dev == NULL)
    {
        debug_tool_usage();
        goto EXIT;
    }

    if (strncasecmp(at_req, "at", 2) != 0)
    {
        printf("invalid at command\n");
        goto EXIT;
    }

    err = Init(dev);
    if (err)
    {
        printf("%s err=%d\n", "Init", err);
        goto EXIT;
    }

    err = GetIsMbimReady(&bValue);
    if (err)
    {
        printf("%s err=%d\n", "GetIsMbimReady", err);
        goto UNINIT;
    }
    if (!bValue)
        goto UNINIT;

    send_at_command(at_req, NULL);

    ret = 0;
UNINIT:
    UnInit();

EXIT:
    if (dev)
        free(dev);

    return ret;
}

int main(int argc, char *argv[])
{
    if (argc >= 5)
    {
        return debug_tool(argc, argv );
    }
    else 
    {
        debug_tool_usage(argv[0]);
        return -1;
    }
}
