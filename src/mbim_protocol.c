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
#include <sys/stat.h>

#include "mbim_protocol.h"
#include "mbim_ctx.h"

#define CRC_16_L_SEED 0xFFFF

/*
 * This mysterious table is just the CRC of each possible byte. It can be
 * computed using the standard bit-at-a-time methods. The polynomial can
 * be seen in entry 128, 0x8408. This corresponds to x^0 + x^5 + x^12.
 * Add the implicit x^16, and you have the standard CRC-CCITT.
 */
static unsigned short const crc_ccitt_table[256] = {
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78};

static inline uint16_t crc_ccitt_byte(uint16_t crc, uint8_t c)
{
    return (crc >> 8) ^ crc_ccitt_table[(crc ^ c) & 0xff];
}

static uint16_t crc_ccitt(unsigned short crc, const uint8_t *buf, size_t len)
{
    while (len--)
        crc = crc_ccitt_byte(crc, *buf++);
    return crc;
}

uint16_t crc16(const uint8_t *buf, size_t len)
{
    uint16_t crc = CRC_16_L_SEED;

    crc = crc_ccitt(crc, buf, len);
    crc ^= CRC_16_L_SEED;

    return crc;
}

static size_t char2wchar(const uint8_t *pSrc, size_t src_len, uint8_t *pDst, size_t dst_len)
{
    size_t i;

    if (src_len > (dst_len / 2))
        src_len = (dst_len / 2);

    for (i = 0; i < src_len; i++)
    {
        *pDst++ = *pSrc++;
        *pDst++ = 0;
    }

    return i * 2;
}

static size_t wchar2char(const uint8_t *pSrc, size_t src_len, uint8_t *pDst, size_t dst_len)
{
    size_t i;

    if (src_len > (dst_len * 2))
        src_len = (dst_len * 2);

    for (i = 0; i < src_len; i += 2)
    {
        *pDst++ = *pSrc++;
        pSrc++;
    }

    return i / 2;
}

static const UUID_T *str2uuid(const char *str)
{
    static UUID_T uuid;
    uint32_t d[16];
    char tmp[16 * 2 + 4 + 1];
    unsigned i = 0;

    while (str[i])
    {
        tmp[i] = tolower(str[i]);
        i++;
    }
    tmp[i] = '\0';

    sscanf(tmp, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
           &d[0], &d[1], &d[2], &d[3], &d[4], &d[5], &d[6], &d[7],
           &d[8], &d[9], &d[10], &d[11], &d[12], &d[13], &d[14], &d[15]);

    for (i = 0; i < 16; i++)
    {
        uuid.uuid[i] = d[i] & 0xFF;
    }

    return &uuid;
}

static uint32_t TransactionId(void)
{
    static uint32_t tid = 0;
    if (tid == 0 || tid == 0x7FFFFFFF)
        tid++;
    return tid++;
}

int mbim_uuid_cmp(const uint8_t *uuid_byte, const char *uuid_str)
{
    return memcmp(uuid_byte, str2uuid(uuid_str), 16);
}

void *mbim_uuid_copy(uint8_t *uuid_byte, const char *uuid_str)
{
    return memcpy(uuid_byte, str2uuid(uuid_str), 16);
}

static int mbim_status_code(MBIM_MESSAGE_HEADER *pMsgHdr)
{
    int status = 0;

    const char *error_str[] = {
        "UNKNOW_0",
        "TIMEOUT_FRAGMENT",
        "FRAGMENT_OUT_OF_SEQUENCE",
        "LENGTH_MISMATCH = 3",
        "DUPLICATED_TID",
        "NOT_OPENED",
        "UNKNOWN",
        "CANCEL",
        "MAX_TRANSFER",
    };

    const char *status_str[] = {
        "SUCCESS",
        "BUSY",
        "FAILURE",
        "SIM_NOT_INSERTED",
        "BAD_SIM",
        "PIN_REQUIRED",
        "PIN_DISABLED",
        "NOT_REGISTERED",
        "PROVIDERS_NOT_FOUND",
        "NO_DEVICE_SUPPORT",
        "PROVIDER_NOT_VISIBLE",
        "DATA_CLASS_NOT_AVAILABL",
        "PACKET_SERVICE_DETACHED",
    };

    switch (pMsgHdr->MessageType)
    {
    case MBIM_OPEN_DONE:
    {
        MBIM_OPEN_DONE_T *pOpenDone = (MBIM_OPEN_DONE_T *)pMsgHdr;
        status = le32toh(pOpenDone->Status);
        if (status)
        {
            mbim_debug("MBIM_OPEN_DONE status: %d (%s)", status,
                       (0 < status && status <= MBIM_STATUS_MAX) ? status_str[status] : "");
        }
    }
    break;
    case MBIM_CLOSE_DONE:
    {
        MBIM_CLOSE_DONE_T *pCloseDone = (MBIM_CLOSE_DONE_T *)pMsgHdr;
        status = le32toh(pCloseDone->Status);
        if (status)
        {
            mbim_debug("MBIM_CLOSE_DONE status: %d (%s)", status,
                       (0 < status && status <= MBIM_STATUS_MAX) ? status_str[status] : "");
        }
    }
    break;
    case MBIM_COMMAND_DONE:
    {
        MBIM_COMMAND_DONE_T *pCmdDone = (MBIM_COMMAND_DONE_T *)pMsgHdr;
        status = le32toh(pCmdDone->Status);
        if (status == 21)
            mbim_debug("MBIM_COMMAND_DONE status: %d (%s)", status,
                       "QBI_MBIM_STATUS_INVALID_PARAMETERS");
        else if (status)
        {
            mbim_debug("MBIM_COMMAND_DONE status: %d (%s)", status,
                       (0 < status && status <= MBIM_STATUS_MAX) ? status_str[status] : "");
        }
    }
    break;
    case MBIM_FUNCTION_ERROR_MSG:
    {
        MBIM_FUNCTION_ERROR_MSG_T *pErrMsg = (MBIM_FUNCTION_ERROR_MSG_T *)pMsgHdr;
        status = le32toh(pErrMsg->ErrorStatusCode);
        if (status)
        {
            mbim_debug("MBIM_FUNCTION_ERROR_MSG status: %d (%s)", status,
                       (0 < status && status <= MBIM_ERROR_MAX) ? error_str[status] : "");
        }
    }
    break;
    default:
        break;
    }

    return status;
}

#define mbim_check_err(err, pRequest, pCmdDone)                                      \
    do                                                                               \
    {                                                                                \
        int _status = 0;                                                             \
        if (pCmdDone)                                                                \
            _status = mbim_status_code(&pCmdDone->MessageHeader);                    \
        if (err || _status)                                                          \
        {                                                                            \
            mbim_debug("%s:%d err=%d, Status=%d", __func__, __LINE__, err, _status); \
            mbim_free(pRequest);                                                     \
            mbim_free(pCmdDone);                                                     \
            if (err)                                                                 \
                return err;                                                          \
            if (_status)                                                             \
                return _status;                                                      \
        }                                                                            \
    } while (0)



static MBIM_MESSAGE_HEADER *mbim_compose_open_message(void)
{
    MBIM_OPEN_MSG_T *pOpen = (MBIM_OPEN_MSG_T*)mbim_alloc(sizeof(MBIM_OPEN_MSG_T));

    if (!pOpen)
        return NULL;

    pOpen->MessageHeader.MessageType = htole32(MBIM_OPEN_MSG);
    pOpen->MessageHeader.MessageLength = htole32(sizeof(MBIM_COMMAND_MSG_T));
    pOpen->MessageHeader.TransactionId = htole32(TransactionId());
    pOpen->MaxControlTransfer = htole32(4096);
    return (MBIM_MESSAGE_HEADER*)pOpen;
}

static MBIM_MESSAGE_HEADER *mbim_compose_close_message(void)
{
    MBIM_CLOSE_MSG_T *pOpen = (MBIM_CLOSE_MSG_T*)mbim_alloc(sizeof(MBIM_CLOSE_MSG_T));

    if (!pOpen)
        return NULL;

    pOpen->MessageHeader.MessageType = htole32(MBIM_CLOSE_MSG);
    pOpen->MessageHeader.MessageLength = htole32(sizeof(MBIM_COMMAND_MSG_T));
    pOpen->MessageHeader.TransactionId = htole32(TransactionId());

    return (MBIM_MESSAGE_HEADER*)pOpen;
}

static MBIM_MESSAGE_HEADER *mbim_compose_command(const char *uuid, uint32_t CID, uint32_t CommandType,
                                                 void *pInformationBuffer, uint32_t InformationBufferLength)
{
    MBIM_COMMAND_MSG_T *pRequest = (MBIM_COMMAND_MSG_T *)mbim_alloc(sizeof(MBIM_COMMAND_MSG_T) + InformationBufferLength);

    if (!pRequest)
        return NULL;

    pRequest->MessageHeader.MessageType = htole32(MBIM_COMMAND_MSG);
    pRequest->MessageHeader.MessageLength = htole32((sizeof(MBIM_COMMAND_MSG_T) + InformationBufferLength));
    pRequest->MessageHeader.TransactionId = htole32(TransactionId());

    pRequest->FragmentHeader.TotalFragments = htole32(1);
    pRequest->FragmentHeader.CurrentFragment = htole32(0);

    mbim_uuid_copy(pRequest->DeviceServiceId.uuid, uuid);

    pRequest->CID = htole32(CID);
    pRequest->CommandType = htole32(CommandType);
    pRequest->InformationBufferLength = htole32(InformationBufferLength);
    if (InformationBufferLength && pInformationBuffer)
        memcpy(pRequest->InformationBuffer, pInformationBuffer, InformationBufferLength);
    else if (InformationBufferLength)
        memset(pRequest->InformationBuffer, 0, InformationBufferLength);

    return &pRequest->MessageHeader;
}


int mbim_proxy_configure(const char *dev)
{
    MBIM_MESSAGE_HEADER *pRequest = NULL;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;
    MBIM_LIBQMI_PROXY_CONFIG_T *cfg;
    int err;

    pRequest = mbim_compose_command(
        UUID_LIBMBIM_PROXY,
        MBIM_CID_PROXY_CONTROL_CONFIGURATION,
        MBIM_CID_CMD_TYPE_SET,
        NULL,
        sizeof(*cfg) + strlen(dev) * 2);
    if (pRequest)
    {
        cfg = (MBIM_LIBQMI_PROXY_CONFIG_T *)((MBIM_COMMAND_MSG_T *)pRequest)->InformationBuffer;

        cfg->DevicePathOffset = sizeof(*cfg);
        cfg->DevicePathSize = char2wchar((const uint8_t *)dev, strlen(dev), cfg->DataBuffer, strlen(dev) * 2);
        cfg->Timeout = 15;
    }

    err = mbim_send_command(pRequest, &pCmdDone);
    mbim_check_err(err, pRequest, pCmdDone);

    mbim_free(pRequest);
    mbim_free(pCmdDone);
    return err;
}

int mbim_OPEN(void)
{
    MBIM_MESSAGE_HEADER *pMsg;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;

    pMsg = mbim_compose_open_message();
    if (pMsg == NULL)
        return -1;

    if (mbim_send_command(pMsg, &pCmdDone) < 0)
    {
        return -1;
    }
    mbim_free(pMsg);
    mbim_free(pCmdDone);

    return 0;
}

int mbim_CLOSE(void)
{
    MBIM_MESSAGE_HEADER *pMsg;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;

    pMsg = mbim_compose_close_message();
    if (pMsg == NULL)
        return -1;

    if (mbim_send_command(pMsg, &pCmdDone) < 0)
    {
        return -1;
    }

    mbim_free(pMsg);
    mbim_free(pCmdDone);

    return 0;
}

int mbim_radio_state_query(MBIM_RADIO_STATE_INFO_T *pRadioState, int is_fcc)
{
    MBIM_MESSAGE_HEADER *pRequest = NULL;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;
    int err;

    mbim_debug("%s()", __func__);
    if (is_fcc)
        pRequest = mbim_compose_command(UUID_QUECTEL, 1, MBIM_CID_CMD_TYPE_QUERY, NULL, 0);
    else
        pRequest = mbim_compose_command(UUID_BASIC_CONNECT, MBIM_CID_RADIO_STATE, MBIM_CID_CMD_TYPE_QUERY, NULL, 0);
    err = mbim_send_command(pRequest, &pCmdDone);
    mbim_check_err(err, pRequest, pCmdDone);

    if (pCmdDone->InformationBufferLength)
    {
        MBIM_RADIO_STATE_INFO_T *pInfo = (MBIM_RADIO_STATE_INFO_T *)pCmdDone->InformationBuffer;
        mbim_debug("HwRadioState: %d, SwRadioState: %d", pInfo->HwRadioState, pInfo->SwRadioState);
        if (pRadioState)
            *pRadioState = *pInfo;
    }

    mbim_free(pRequest);
    mbim_free(pCmdDone);
    return err;
}

int mbim_radio_state_set(MBIM_RADIO_SWITCH_STATE_E RadioState, int is_fcc)
{
    MBIM_MESSAGE_HEADER *pRequest = NULL;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;
    uint32_t value = htole32(RadioState);
    int err;

    mbim_debug("%s( %d )", __func__, RadioState);
    if (is_fcc)
        pRequest = mbim_compose_command(UUID_QUECTEL, 1, MBIM_CID_CMD_TYPE_SET, &value, sizeof(value));
    else
        pRequest = mbim_compose_command(UUID_BASIC_CONNECT, MBIM_CID_RADIO_STATE, MBIM_CID_CMD_TYPE_SET, &value, sizeof(value));
    err = mbim_send_command(pRequest, &pCmdDone);
    mbim_check_err(err, pRequest, pCmdDone);

    if (le32toh(pCmdDone->InformationBufferLength))
    {
        MBIM_RADIO_STATE_INFO_T *pInfo = (MBIM_RADIO_STATE_INFO_T *)pCmdDone->InformationBuffer;
        mbim_debug("HwRadioState: %d, SwRadioState: %d", le32toh(pInfo->HwRadioState), le32toh(pInfo->SwRadioState));
    }

    mbim_free(pRequest);
    mbim_free(pCmdDone);
    return err;
}

int mbim_device_caps_query(char *pHardwareInfo, size_t output_len)
{
    MBIM_MESSAGE_HEADER *pRequest = NULL;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;
    int err;

    if (pHardwareInfo)
        pHardwareInfo[0] = '\0';

    mbim_debug("%s()", __func__);
    pRequest = mbim_compose_command(UUID_BASIC_CONNECT, MBIM_CID_DEVICE_CAPS, MBIM_CID_CMD_TYPE_QUERY, NULL, 0);
    err = mbim_send_command(pRequest, &pCmdDone);
    mbim_check_err(err, pRequest, pCmdDone);

    if (le32toh(pCmdDone->InformationBufferLength))
    {
        MBIM_DEVICE_CAPS_INFO_T *pInfo = (MBIM_DEVICE_CAPS_INFO_T *)pCmdDone->InformationBuffer;
        char tmp[32];
        size_t len;

        if (le32toh(pInfo->DeviceIdOffset) && le32toh(pInfo->DeviceIdSize))
        {
            len = wchar2char((uint8_t *)pInfo + le32toh(pInfo->DeviceIdOffset), le32toh(pInfo->DeviceIdSize), (uint8_t *)tmp, sizeof(tmp) - 1),
            tmp[len] = '\0';
            mbim_debug("DeviceId:     %s", tmp);
        }

        if (le32toh(pInfo->FirmwareInfoOffset) && le32toh(pInfo->FirmwareInfoSize))
        {
            len = wchar2char((uint8_t *)pInfo + le32toh(pInfo->FirmwareInfoOffset), le32toh(pInfo->FirmwareInfoSize), (uint8_t *)tmp, sizeof(tmp) - 1),
            tmp[len] = '\0';
            mbim_debug("FirmwareInfo: %s", tmp);
        }

        if (le32toh(pInfo->HardwareInfoOffset) && le32toh(pInfo->HardwareInfoSize))
        {
            len = wchar2char((uint8_t *)pInfo + le32toh(pInfo->HardwareInfoOffset), le32toh(pInfo->HardwareInfoSize), (uint8_t *)tmp, sizeof(tmp) - 1),
            tmp[len] = '\0';
            mbim_debug("HardwareInfo: %s", tmp);
            if (pHardwareInfo)
                strncpy(pHardwareInfo, tmp, output_len);
        }
    }

    mbim_free(pRequest);
    mbim_free(pCmdDone);
    return err;
}

int mbim_device_service_subscribe_list_set(const char *uuid, uint32_t CID[], uint32_t CidCount)
{
    MBIM_MESSAGE_HEADER *pRequest = NULL;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;
    MBIM_DEVICE_SERVICE_SUBSCRIBE_LIST_T *list;
    MBIM_EVENT_ENTRY_T *entry;
    uint32_t ElementCount = 1;
    int err;

    mbim_debug("%s(uuid=%s)", __func__, uuid);
    /* mbim-proxy will merge all service subscribe list for all clients to set on device */
    pRequest = mbim_compose_command(UUID_BASIC_CONNECT,
                                    MBIM_CID_DEVICE_SERVICE_SUBSCRIBE_LIST,
                                    MBIM_CID_CMD_TYPE_SET,
                                    NULL,
                                    sizeof(*list) + ElementCount * sizeof(OL_PAIR_LIST) + sizeof(*entry) + CidCount * sizeof(uint32_t));
    if (pRequest)
    {
        uint32_t i;
        list = (MBIM_DEVICE_SERVICE_SUBSCRIBE_LIST_T *)((MBIM_COMMAND_MSG_T *)pRequest)->InformationBuffer;

        list->ElementCount = ElementCount;
        list->DeviceServiceSubscribeRefList[0].offset = sizeof(*list) + ElementCount * sizeof(OL_PAIR_LIST);
        list->DeviceServiceSubscribeRefList[0].size = sizeof(*entry) + CidCount * sizeof(uint32_t);

        entry = (MBIM_EVENT_ENTRY_T *)((uint8_t *)list + list->DeviceServiceSubscribeRefList[0].offset);
        mbim_uuid_copy(entry->DeviceServiceId.uuid, uuid);
        entry->CidCount = CidCount;
        for (i = 0; i < CidCount; i++)
            entry->DataBuffer[i] = CID[i];
    }

    err = mbim_send_command(pRequest, &pCmdDone);
    mbim_check_err(err, pRequest, pCmdDone);

    mbim_free(pRequest);
    mbim_free(pCmdDone);
    return err;
}

int mbim_SetSarEnable(int Value)
{
    MBIM_MESSAGE_HEADER *pRequest = NULL;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;
    int err;

#define QL_MBIM_DIAG_OPEN 0x0012
#define QL_MBIM_DIAG_CLOSE 0x0022
    typedef struct
    {
        uint16_t diag_cfg;
    } ql_diag_config_s_req_s;
    ql_diag_config_s_req_s *req;

    mbim_debug("%s(Value=%u)", __func__, Value);
    pRequest = mbim_compose_command(uuid_qmbe, QUECTEL_QBI_SVC_QMBE_MBIM_CID_DIAG_OVER_MBIM_CFG,
                                    MBIM_CID_CMD_TYPE_SET, NULL, sizeof(*req));
    if (pRequest)
    {
        req = (ql_diag_config_s_req_s *)((MBIM_COMMAND_MSG_T *)pRequest)->InformationBuffer;

        req->diag_cfg = htobe16(Value ? QL_MBIM_DIAG_OPEN : QL_MBIM_DIAG_CLOSE);
    }
    err = mbim_send_command(pRequest, &pCmdDone);
    mbim_check_err(err, pRequest, pCmdDone);

    if (le32toh(pCmdDone->InformationBufferLength))
    {
    }

    mbim_free(pRequest);
    mbim_free(pCmdDone);
    return err;
}

int mbim_GetSarEnable(int *pValue)
{
    MBIM_MESSAGE_HEADER *pRequest = NULL;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;
    int err;

    typedef struct
    {
        uint32_t diag_config;
    } qbi_svc_qmbe_diag_config_rsp_s;
    qbi_svc_qmbe_diag_config_rsp_s *rsp;

    if (pValue)
        *pValue = -1;
    mbim_debug("%s()", __func__);
    pRequest = mbim_compose_command(uuid_qmbe, QUECTEL_QBI_SVC_QMBE_MBIM_CID_DIAG_OVER_MBIM_CFG, MBIM_CID_CMD_TYPE_QUERY, NULL, 0);
    err = mbim_send_command(pRequest, &pCmdDone);
    mbim_check_err(err, pRequest, pCmdDone);

    if (le32toh(pCmdDone->InformationBufferLength))
    {
        rsp = (qbi_svc_qmbe_diag_config_rsp_s *)pCmdDone->InformationBuffer;

        mbim_debug("\tdiag_config: %u", rsp->diag_config);
        if (pValue)
            *pValue = !!rsp->diag_config;
    }

    mbim_free(pRequest);
    mbim_free(pCmdDone);
    return err;
}

static char *md5sum_str(const unsigned char md5sum[16])
{
    static char s[16 * 2 + 1];
    int i;

    for (i = 0; i < 16; i++)
        sprintf(&s[i * 2], "%02x", md5sum[i]);
    return s;
}

static uint8_t nv_data[RFNV_DATA_SIZE_MAX * 2];
static size_t hdlc_code(const uint8_t *pSrc, size_t src_len, uint8_t *pDst, size_t dst_len)
{
    size_t n, k;

    k = 0;
    for (n = 0; n < src_len && k < dst_len; n++)
    {
        if (*pSrc == 0x7E || *pSrc == 0x7D)
        {
            *pDst++ = 0x7D;
            *pDst++ = (0x20 ^ *pSrc++);
            k += 2;
        }
        else
        {
            *pDst++ = *pSrc++;
            k += 1;
        }
    }

    *pDst++ = 0x7e;
    k++;

    return k;
}

static int hdlc_decode(const uint8_t *pSrc, size_t src_len, uint8_t *pDrc, size_t *drc_len)
{
    const uint8_t *ql_data = NULL;
    unsigned int data_len = 0;
    uint8_t crc_ql_data = 0;
    unsigned int t = 0;
    uint16_t ql_crc = CRC_16_L_SEED;
    uint8_t ql_sent_crc[2] = {0, 0};
    uint8_t ql_sent_crc_temp[2] = {0, 0};
    int err = 0;
    int drc_data_len = 0;
    /*-------------------------------------------------------------------------*/
    if (drc_len != NULL)
    {
        *drc_len = 0;
    }
    ql_data = pSrc;
    data_len = src_len - 3;

    ////////////////////////Add CRC,7D 7E detect start//////////////////////
    /* CRC-16,7D5E-----ql_data---5E7D*/
    ql_sent_crc_temp[0] = ql_data[src_len - 3];
    ql_sent_crc_temp[1] = ql_data[src_len - 2];
    if ((ql_sent_crc_temp[1] == 0x5D) && (ql_sent_crc_temp[0] == 0x7D))
    {
        ql_sent_crc[1] = 0x7D;
        data_len = data_len - 1;
    }
    else if ((ql_sent_crc_temp[1] == 0x5E) && (ql_sent_crc_temp[0] == 0x7D))
    {
        ql_sent_crc[1] = 0x7E;
        data_len = data_len - 1;
    }
    else
    {
        ql_sent_crc[1] = ql_data[src_len - 2];
    }
    ql_sent_crc_temp[0] = 0;
    ql_sent_crc_temp[1] = 0;
    if ((ql_sent_crc[1] == 0x7D) || (ql_sent_crc[1] == 0x7E))
    {
        ql_sent_crc_temp[0] = ql_data[src_len - 5];
        ql_sent_crc_temp[1] = ql_data[src_len - 4];
        if ((ql_sent_crc_temp[1] == 0x5D) && (ql_sent_crc_temp[0] == 0x7D))
        {
            ql_sent_crc[0] = 0x7D;
            data_len = data_len - 1;
        }
        else if ((ql_sent_crc_temp[1] == 0x5E) && (ql_sent_crc_temp[0] == 0x7D))
        {
            ql_sent_crc[0] = 0x7E;
            data_len = data_len - 1;
        }
        else
        {
            ql_sent_crc[0] = ql_data[src_len - 4];
        }
    }
    else
    {
        ql_sent_crc_temp[0] = ql_data[src_len - 4];
        ql_sent_crc_temp[1] = ql_data[src_len - 3];
        if ((ql_sent_crc_temp[1] == 0x5D) && (ql_sent_crc_temp[0] == 0x7D))
        {
            ql_sent_crc[0] = 0x7D;
            data_len = data_len - 1;
        }
        else if ((ql_sent_crc_temp[1] == 0x5E) && (ql_sent_crc_temp[0] == 0x7D))
        {
            ql_sent_crc[0] = 0x7E;
            data_len = data_len - 1;
        }
        else
        {
            ql_sent_crc[0] = ql_data[src_len - 3];
        }
    }
    ///////////////////////Add CRC,7D 7E detect end/////////////////////////
    for (t = 0; t < data_len; t++)
    {
        crc_ql_data = *(ql_data + t);
        if (*(ql_data + t) == 0x7d)
        {
            if (*(ql_data + t + 1) == 0x5e) /*7E*/
            {
                t++;
                crc_ql_data = 0x7E;
                // mbim_debug("[quectel][mbim]diag: detect 0x7D 0x5E,change to 7E\n");
            }
            else if (*(ql_data + t + 1) == 0x5d) /*7D*/
            {
                t++;
                crc_ql_data = 0x7D;
                // mbim_debug("[quectel][mbim]diag: detect 0x7D 0x5D,change to 7D\n");
            }
        }
        if (pDrc != NULL)
        {
            *(pDrc + drc_data_len) = crc_ql_data;
        }

        drc_data_len++;
        ql_crc = crc_ccitt_byte(ql_crc, crc_ql_data);
    }
    ql_crc ^= CRC_16_L_SEED;
    if (drc_len != NULL)
    {
        *drc_len = drc_data_len;
    }

    if (ql_crc != *((uint16_t *)ql_sent_crc))
    {
        mbim_debug("[quectel][mbim]diag: In %s, crc mismatch. expected: %x, sent %x.\n",
                   __func__, ql_crc, *((uint16_t *)ql_sent_crc));
        err = -1;
    }

    return err;
} /* hdlc_decode */

static int ind_msg_buff[2048] = {0};
static int check_SetSarDataPacketStatus(char *data, int len)
{
    int err = 0;
    // 4B 0B/*FTM =header->subsys_id */
    // 24 00/*rfnv====36*/
    // 78 02/*631--write*/
    // 00 00 /* set to 0 for RFNV */
    // 0E 00 /* cmd_rsp_pkt_size*/
    // 02 00   /*err_code hope 02==no error===RFCOMMON_NV_WRITE_SUCCESS*/
    // B3 73  /*NV 29619*/
    // 80 07 /*CRC*/
    // 7E /*end char*/

    if (hdlc_decode(data, len, NULL, NULL) != 0)
    {
        err = -1;
    }
    else if ((len > 14 /*14 char*/) && (data[0] == 0x4B) && (data[1] == 0x0B) && (data[2] == 0x24) && (data[3] == 0x00) && (data[4] == 0x78) && (data[5] == 0x02) && (data[6] == 0x00) && (data[7] == 0x00) && (data[8] == 0x0e) && (data[9] == 0x00) && (data[10] == 0x02 /*RFCOMMON_NV_WRITE_SUCCESS*/) && (data[11] == 0x00) && (data[12] == 0xFD) && (data[13] == 0xff))
    {
        err = 0;
    }
    else
    {
        mbim_debug("%s, Error ,msg_len:%d,data[0]:%x,data[1]:%x,data[2]:%x,data[3]:%x,data[4]:%x,\
     data[5]:%x,data[6]:%x,data[7]:%x,data[8]:%x,data[9]:%x,data[10]:%x,data[11]:%x,data[12]:%x,data[13]:%x",
                   __func__, len, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                   data[8], data[9], data[10], data[11], data[12], data[13]);

        err = -2;
    }

    return err;
}

int mbim_SetSarValue(char *path, int nv)
{
    struct stat st;
    char *file_data;
    int file_size;
    int fd;

    MBIM_MESSAGE_HEADER *pRequest = NULL;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;
    DIAG_OVER_MBIM_WRITE_DATA_REQ *write_req;
    size_t cur = 0;
    int err;
    int busy_mask = 0;
    int busy_timers = 0;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) != 0)
    {
        close(fd);
        return 0;
    }

    file_size = st.st_size;

    file_data = calloc(1, file_size);
    if (file_data == NULL)
    {
        close(fd);
        return -1;
    }

    if (read(fd, file_data, file_size) != file_size)
    {
        close(fd);
        free(file_data);
        return -1;
    }

    close(fd);

    write_req = (DIAG_OVER_MBIM_WRITE_DATA_REQ *)nv_data;

    // 4b 0b/*FTM =header->subsys_id */
    // 24 00/*rfnv====36*/
    // 78 02/*631--write*/
    // 00 00  /* set to 0 for RFNV */
    // 0e 00 /* cmd_rsp_pkt_size*/
    // b3 73/*NV 29619*/
    // 00 00/*rfnv_item_size write len*/
    // 01 00/*rfnv_append_data start  is 0，then 1*/
    // rfnv_item_data[RFNV_DATA_SIZE_MAX==3800]
    // 05 f0/*CRC*/
    // 7e/*end char*/
    write_req->subsysid = 0x0b4b;
    write_req->rf_nv = 0x0024;
    write_req->write_cmd = 0x0278;
    write_req->nv_index = 0;
    write_req->pkt_size = 0;
    write_req->nv_flag = nv;

    mbim_debug("%s(size=%d)", __func__, file_size);

    for (cur = 0; cur < file_size; cur += RFNV_DATA_SIZE_MAX)
    {
        pRequest = mbim_compose_command(uuid_qmbe, QUECTEL_QBI_SVC_QMBE_MBIM_CID_DIAG_DATA,
                                        MBIM_CID_CMD_TYPE_SET, NULL, sizeof(nv_data));

        if ((busy_mask == 1) && (cur > 0))
        {
            cur -= RFNV_DATA_SIZE_MAX;
            if (busy_timers > 3 /*max 3 timers retry*/)
            {
                mbim_debug("%s(busy 3 timers retry fail)", __func__);
                err = -1;
                break;
            }
        }
        if (pRequest)
        {
            size_t len = sizeof(DIAG_OVER_MBIM_WRITE_DATA_REQ);

            write_req->item_size = file_size - cur;
            if (write_req->item_size > RFNV_DATA_SIZE_MAX)
                write_req->item_size = RFNV_DATA_SIZE_MAX;
            write_req->item_index = (cur != 0);
            memcpy(write_req->item_data, file_data + cur, write_req->item_size);
            len += write_req->item_size;
            *(uint16_t *)((uint8_t *)write_req + len) = crc16((const uint8_t *)write_req, len);
            len += 2;

            len = hdlc_code((const uint8_t *)write_req, len,
                            (uint8_t *)((MBIM_COMMAND_MSG_T *)pRequest)->InformationBuffer, sizeof(nv_data));

            ((MBIM_COMMAND_MSG_T *)pRequest)->InformationBufferLength = htole32(len);
            pRequest->MessageLength = htole32((sizeof(MBIM_COMMAND_MSG_T) + len));
        }

        // mbim_debug("%s(cur=%zd)", __func__, cur);
        err = mbim_send_command(pRequest, &pCmdDone);
        if (pCmdDone == NULL)
            break;

        if ((pCmdDone->Status == MBIM_STATUS_BUSY))
            ;
        else
            mbim_check_err(err, pRequest, pCmdDone);

        if (le32toh(pCmdDone->Status == MBIM_STATUS_BUSY))
        {
            mbim_debug("%s,mbim status busy,now delay 200mS resend", __func__);
            usleep(200 * 1000);
            busy_mask = 1;
            busy_timers++;
            continue;
        }
        else if (busy_timers > 0)
        {
            busy_timers--;
            if (check_SetSarDataPacketStatus(pCmdDone->InformationBuffer, pCmdDone->InformationBufferLength) != 0)
            {
                err = -2;
                break;
            }
        }
        mbim_free(pRequest);
        mbim_free(pCmdDone);
    }

    free(file_data);
    mbim_free(pRequest);
    mbim_free(pCmdDone);
    return err;
}

int mbim_GetSarValue(unsigned char *pValue, unsigned short *size)
{
#define GET_BYTES_MAX_LOOP 12
    MBIM_MESSAGE_HEADER *pRequest = NULL;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;
    DIAG_OVER_MBIM_READ_DATA_REQ *read_req;
    int err;
    int busy_mask = 0;
    int busy_timers = 0;
    /*****************decode ind msg start***********************************/
    MBIM_INDICATE_STATUS_MSG_T *pInd = NULL;
    uint8_t *data = NULL;
    uint8_t GetIndDataBuff[1024 * 5 /*single packet len 4K*/] = {0};
    size_t GetIndDataBuffLen = 0;
    size_t NVsarGetDataBytesReadLen = 0;
    size_t NVsarGetDataBytesRemainingLen = 0;

    size_t NVsarGetDataBytesMaxLoop = GET_BYTES_MAX_LOOP /*3.8K * 10 = 38K force break and error*/;
    /*****************decode ind msg end **********************************/

    memset(nv_data, 0, sizeof(nv_data));
    read_req = (DIAG_OVER_MBIM_READ_DATA_REQ *)nv_data;

    // 4b 0b/*FTM =header->subsys_id */
    // 24 00/*rfnv====36*/
    // 77 02/*631--read*/
    // 00 00  /* set to 0 for RFNV */
    // 00 00 /* set to 0 for RFNV */
    // b3 73/*NV 29619*/
    // 00 00/*req_rfnv_offset*/
    // 05 f0 /*CRC*/
    // 7e/*end char*/
    read_req->subsysid = 0x0b4b;
    read_req->rf_nv = 0x0024;
    read_req->read_cmd = 0x0277;
    read_req->nv_index = 0;
    read_req->pkt_size = 0;
    read_req->nv_flag = 0xFFFD;

    do
    {
        if (busy_mask == 1)
        {
            read_req->nv_offset -= NVsarGetDataBytesReadLen;
            if (busy_timers > 3 /*max 3 timers retry*/)
            {
                mbim_debug("%s(busy 3 timers retry fail)", __func__);
                err = -1;
                break;
            }
        }
        pRequest = mbim_compose_command(uuid_qmbe, QUECTEL_QBI_SVC_QMBE_MBIM_CID_DIAG_DATA,
                                        MBIM_CID_CMD_TYPE_SET, NULL, sizeof(nv_data));
        if (pRequest)
        {
            unsigned len;

            read_req->nv_offset += NVsarGetDataBytesReadLen;
            read_req->crc = crc16((const uint8_t *)read_req, sizeof(*read_req) - 3);

            len = hdlc_code((const uint8_t *)read_req, sizeof(*read_req) - 1,
                            (uint8_t *)((MBIM_COMMAND_MSG_T *)pRequest)->InformationBuffer, sizeof(nv_data));

            ((MBIM_COMMAND_MSG_T *)pRequest)->InformationBufferLength = htole32(len);
            pRequest->MessageLength = htole32((sizeof(MBIM_COMMAND_MSG_T) + len));
        }

        // mbim_debug("%s(nv_offset=%zd)", __func__,read_req->nv_offset);
        err = mbim_send_command(pRequest, &pCmdDone);
        mbim_check_err(err, pRequest, pCmdDone);

        if (le32toh(pCmdDone->Status == MBIM_STATUS_BUSY))
        {
            mbim_debug("%s,mbim status busy,now delay 200mS resend", __func__);
            usleep(200 * 1000);
            busy_mask = 1;
            busy_timers++;
            continue;
        }
        else if (busy_timers > 0)
        {
            busy_timers--;
        }

        mbim_free(pRequest);
    
        /********************************************************************************/
        // 响应帧（Mbim Event方式 告知Host\EF\BC?   //4B 0B /*FTM =header->subsys_id */
        // 24 00 /*rfnv====36*/
        // 77 02 /*631--read*/
        // 00 00   /*cmd_data_len;       set to 0 for RFNV */
        // EC 0E  /* cmd_rsp_pkt_size;   set to 0 for RFNV */
        // 00 00  /*err_code*/
        // B3 73 /*NV 29619*/
        // D8 0E /*bytes_read=3800*/
        // CE 55 /*低二\E4\BD?bytes_remaining=21966 ,模块NV29619 还剩余多少未读取*/
        // 00 00 /*高二\E4\BD?0*/
        //.....rfnv_item_data[RFNV_DATA_SIZE_MAX==3800]
        //  A9 6A  /*CRC*/
        // 7E  /*end char*/

        data = pCmdDone->InformationBuffer;

        if (hdlc_decode(data, pCmdDone->InformationBufferLength, GetIndDataBuff, &GetIndDataBuffLen) != 0)
        {
            err = -1;
            break;
        }
        else
        {
            NVsarGetDataBytesReadLen = GetIndDataBuff[14] + GetIndDataBuff[15] * 256;
            NVsarGetDataBytesRemainingLen = GetIndDataBuff[16] + GetIndDataBuff[17] * 256; /*NV29619 Max 30K byte,So drop High 2 bytes remaining check*/
            if (NVsarGetDataBytesMaxLoop == GET_BYTES_MAX_LOOP)
            {
                *size = NVsarGetDataBytesReadLen + NVsarGetDataBytesRemainingLen;
            }
            mbim_debug("%s,BytesReadLen:%zd,BytesRemainingLen:%zd", __func__, NVsarGetDataBytesReadLen, NVsarGetDataBytesRemainingLen);
            if (NVsarGetDataBytesReadLen > 4096 /*4K*/)
            {
                err = -2;
                mbim_debug("ERROR:too long msg,%s,BytesReadLen:%zd,BytesRemainingLen:%zd", __func__, NVsarGetDataBytesReadLen, NVsarGetDataBytesRemainingLen);
                break;
            }

            memcpy(pValue + read_req->nv_offset, &GetIndDataBuff[20], NVsarGetDataBytesReadLen);
            err = 0;
        }
        NVsarGetDataBytesMaxLoop--;
        if (NVsarGetDataBytesMaxLoop == 0)
        {
            err = -3;
            mbim_debug("ERROR:Max Loop,%s,BytesReadLen:%zd,BytesRemainingLen:%zd", __func__, NVsarGetDataBytesReadLen, NVsarGetDataBytesRemainingLen);
            break;
        }
        /********************************************************************************/
    } while (NVsarGetDataBytesRemainingLen != 0);

    // out:
    mbim_free(pRequest);
    mbim_free(pCmdDone);
    return err;
}

int mbim_SetSarLevel(int Value)
{
    MBIM_MESSAGE_HEADER *pRequest = NULL;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;
    MBIM_MS_SET_SAR_CONFIG_T *req;
    MBIM_MS_SAR_CONFIG_STATE_T *sarData;
    uint32_t ElementCount = 1;
    int err;

    mbim_debug("%s(Value=%u)", __func__, Value);
    pRequest = mbim_compose_command(UUID_MS_SARControl, MBIM_CID_MS_SAR_CONFIG,
                                    MBIM_CID_CMD_TYPE_SET, NULL, sizeof(*req) + (sizeof(*sarData) + sizeof(OL_PAIR_LIST)) * ElementCount);
    if (pRequest)
    {
        req = (MBIM_MS_SET_SAR_CONFIG_T *)((MBIM_COMMAND_MSG_T *)pRequest)->InformationBuffer;
        uint32_t i;

        req->SARMode = MBIMMsSARControlModeOS;
        req->SARBackOffStatus = MBIMMsSARBackOffStatusEnabled;
        req->ElementCount = ElementCount;

        for (i = 0; i < req->ElementCount; i++)
        {
            req->SARConfigStatusRefList[i].offset = sizeof(*req) + sizeof(*sarData) * i + sizeof(OL_PAIR_LIST) * ElementCount;
            req->SARConfigStatusRefList[i].size = sizeof(OL_PAIR_LIST);
            sarData = (MBIM_MS_SAR_CONFIG_STATE_T *)((uint8_t *)req + le32toh(req->SARConfigStatusRefList[i].offset));
            sarData->SARAntennaIndex = 0xFFFFFFFF;
            sarData->SARBAckOffIndex = Value;
        }
    }
    err = mbim_send_command(pRequest, &pCmdDone);
    mbim_check_err(err, pRequest, pCmdDone);

    if (le32toh(pCmdDone->InformationBufferLength))
    {
    }

    // out:
    mbim_free(pRequest);
    mbim_free(pCmdDone);
    return err;
}

int mbim_SetDeviceReboot(int Value)
{
    MBIM_MESSAGE_HEADER *pRequest = NULL;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;
    MBIM_DEVICE_REBOOT *req;
    int err;

    mbim_debug("%s(Value=%x)", __func__, Value);
    pRequest = mbim_compose_command(uuid_qmbe, QUECTEL_QBI_SVC_QMBE_MBIM_CID_REBOOT,
                                    MBIM_CID_CMD_TYPE_SET, NULL, sizeof(*req));
    if (pRequest)
    {
        req = (MBIM_DEVICE_REBOOT *)((MBIM_COMMAND_MSG_T *)pRequest)->InformationBuffer;

        req->reboot_mode = htobe16(Value);
    }
    err = _mbim_send_command(pRequest, &pCmdDone, 3);
    if (err == 110)
        return 0;
    mbim_check_err(err, pRequest, pCmdDone);

    if (le32toh(pCmdDone->InformationBufferLength))
    {
    }

    // out:
    mbim_free(pRequest);
    mbim_free(pCmdDone);
    return err;
}


int mbim_get_efs_md5(int nv, unsigned char md5[16])
{
    MBIM_MESSAGE_HEADER *pRequest = NULL;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;
    uint32_t value = htobe32(nv);
    int err;

    pRequest = mbim_compose_command(uuid_qmbe, QUECTEL_QBI_SVC_QMBE_MBIM_CID_MD5, MBIM_CID_CMD_TYPE_SET, &value, sizeof(value));
    err = mbim_send_command(pRequest, &pCmdDone);
    mbim_check_err(err, pRequest, pCmdDone);

    if (le32toh(pCmdDone->InformationBufferLength) == 16)
    {
        memcpy(md5, pCmdDone->InformationBuffer, 16);
    }

    mbim_free(pRequest);
    mbim_free(pCmdDone);
    return err;
}

static char s_atc_response[8192];
int mbim_send_at_command(const char *atc_req, char **pp_atc_rsp)
{
    MBIM_MESSAGE_HEADER *pRequest = NULL;
    MBIM_COMMAND_DONE_T *pCmdDone = NULL;
    int err;
    size_t atc_len = strlen(atc_req);

    if (pp_atc_rsp)
        *pp_atc_rsp = NULL;
    printf("Send > %s\n", atc_req);
    pRequest = mbim_compose_command(uuid_qdu, 8,
                                    MBIM_CID_CMD_TYPE_SET, NULL, 4 + atc_len);
    if (pRequest)
    {
        char *pbuf = (char *)((MBIM_COMMAND_MSG_T *)pRequest)->InformationBuffer;

        memset(pbuf, 0, 4);
        memcpy(pbuf + 4, atc_req, atc_len);
    }
    err = mbim_send_command(pRequest, &pCmdDone);
    mbim_check_err(err, pRequest, pCmdDone);

    if (le32toh(pCmdDone->InformationBufferLength))
    {
        unsigned int i = 0;

        strncpy(s_atc_response, (char *)&pCmdDone->InformationBuffer[4], pCmdDone->InformationBufferLength - 4);
        s_atc_response[pCmdDone->InformationBufferLength - 4] = 0;

        printf("Recv < %s", s_atc_response);
        if (pp_atc_rsp)
            *pp_atc_rsp = s_atc_response;
    }

    // out:
    mbim_free(pRequest);
    mbim_free(pCmdDone);
    return err;
}
