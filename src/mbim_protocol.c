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
