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

#ifndef _API_H_
#define _API_H_

typedef int BOOL;

extern BOOL mbim_tool_debug;

 int Init(const char *dev_path);
 int GetIsMbimReady(BOOL *bValue);
 int GetFileMD5SUM(char *path, unsigned char md5[16]);
 int GetEFSMD5SUM(int nv, unsigned char md5[16]);
 int send_at_command(char *at_req, char **at_resp);
 void UnInit(void);

#endif
