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

extern FILE *log_fp;
const char *get_time(void);

extern pthread_mutex_t log_mutex;
#define mbim_debug(fmt, args...)                                   \
	do                                                             \
	{                                                              \
		pthread_mutex_lock(&log_mutex);                            \
		if (log_fp)                                                \
			fprintf(log_fp, "[%s] " fmt "\n", get_time(), ##args); \
		pthread_mutex_unlock(&log_mutex);                          \
	} while (0)
#define mbim_alloc(_size) malloc(_size)
#define mbim_free(_mem)  \
	do                   \
	{                    \
		if (_mem)        \
		{                \
			free(_mem);  \
			_mem = NULL; \
		}                \
	} while (0)
#define mbim_fd_close(_fd) \
	do                  \
	{                   \
		if (_fd != -1)  \
		{               \
			close(_fd); \
			_fd = -1;   \
		}               \
	} while (0)
void mbim_dump(MBIM_MESSAGE_HEADER *pMsg, int verbose);

extern int mbim_ctx_init(int verbose);
extern void mbim_ctx_deinit(void);
extern int mbim_is_ready(const char *dev);
extern int mbim_send_command(MBIM_MESSAGE_HEADER *pRequest, MBIM_COMMAND_DONE_T **ppCmdDone);
extern int _mbim_send_command(MBIM_MESSAGE_HEADER *pRequest, MBIM_COMMAND_DONE_T **ppCmdDone, unsigned t_sec);
