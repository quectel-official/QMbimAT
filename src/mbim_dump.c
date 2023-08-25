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
#include <limits.h>
#include <inttypes.h>
#include <linux/un.h>
#include "mbim_protocol.h"
#include "mbim_ctx.h"

#define return_enumstr(_val, _enumstr)                                            \
    do                                                                            \
    {                                                                             \
        int idx;                                                                  \
        for (idx = 0; idx < (int)(sizeof(_enumstr) / sizeof(_enumstr[0])); idx++) \
        {                                                                         \
            if (_val == _enumstr[idx].val)                                        \
                return _enumstr[idx].name;                                        \
        }                                                                         \
    } while (0);

static const char *uuid2str(const UUID_T *pUUID)
{
    static char str[16 * 2 + 4 + 1];
    const uint8_t *d = pUUID->uuid;

    snprintf(str, sizeof(str), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
             d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]);

    return str;
}

static const char *DeviceServiceId2str(const UUID_T *pUUID)
{
    const char *str = uuid2str(pUUID);

    struct
    {
        char *val;
        char *name;
    } _enumstr[] = {
        {UUID_BASIC_CONNECT, "UUID_BASIC_CONNECT"},
        {UUID_BASIC_CONNECT_EXT, "UUID_BASIC_CONNECT_EXT"},
        {UUID_SMS, "UUID_SMS"},
        {UUID_USSD, "UUID_USSD"},
        {UUID_PHONEBOOK, "UUID_PHONEBOOK"},
        {UUID_STK, "UUID_STK"},
        {UUID_AUTH, "UUID_AUTH"},
        {UUID_DSS, "UUID_DSS"},
        {uuid_ext_qmux, "uuid_ext_qmux"},
        {uuid_mshsd, "uuid_mshsd"},
        {uuid_qmbe, "uuid_qmbe"},
        {UUID_MSFWID, "UUID_MSFWID"},
        {uuid_atds, "uuid_atds"},
        {uuid_qdu, "uuid_qdu"},
        {UUID_MS_UICC_LOW_LEVEL, "UUID_MS_UICC_LOW_LEVEL"},
        {UUID_MS_SARControl, "UUID_MS_SARControl"},
        {UUID_VOICEEXTENSIONS, "UUID_VOICEEXTENSIONS"},
        {UUID_VOICEEXTENSIONS, "UUID_LIBMBIM_PROXY"},
    };
    int idx;

    for (idx = 0; idx < (int)(sizeof(_enumstr) / sizeof(_enumstr[0])); idx++)
    {
        if (!strcasecmp(str, _enumstr[idx].val))
            return _enumstr[idx].name;
    }

    return str;
}

static const char *mbim_get_segment(void *_pMsg, uint32_t offset, uint32_t len)
{
    int idx;
    static char buff[256] = {'\0'};
    uint8_t *pMsg = (uint8_t *)_pMsg;

    for (idx = 0; idx < (int)(len / 2); idx++)
        buff[idx] = pMsg[offset + idx * 2];
    buff[idx] = '\0';
    return buff;
}

static const char *MBIMActivationStateStr(int _val)
{
    struct
    {
        int val;
        char *name;
    } _enumstr[] = {
        {MBIMActivationStateUnknown, "Unknown"},
        {MBIMActivationStateActivated, "Activated"},
        {MBIMActivationStateActivating, "Activating"},
        {MBIMActivationStateDeactivated, "Deactivated"},
        {MBIMActivationStateDeactivating, "Deactivating"},
    };
    int idx;

    for (idx = 0; (int)(sizeof(_enumstr) / sizeof(_enumstr[0])); idx++)
    {
        if (_val == _enumstr[idx].val)
            return _enumstr[idx].name;
    }

    return "Undefined";
};

static const char *MBIMVoiceCallStateStr(int _val)
{
    struct
    {
        int val;
        char *name;
    } _enumstr[] = {
        {MBIMVoiceCallStateNone, "None"},
        {MBIMVoiceCallStateInProgress, "InProgress"},
        {MBIMVoiceCallStateHangUp, "HangUp"},
    };
    int idx;

    for (idx = 0; (int)(sizeof(_enumstr) / sizeof(_enumstr[0])); idx++)
    {
        if (_val == _enumstr[idx].val)
            return _enumstr[idx].name;
    }

    return "Undefined";
};

static const char *MBIMRegisterStateStr(int _val)
{
    struct
    {
        int val;
        char *name;
    } _enumstr[] = {
        {MBIMRegisterStateUnknown, "Unknown"},
        {MBIMRegisterStateDeregistered, "Deregistered"},
        {MBIMRegisterStateSearching, "Searching"},
        {MBIMRegisterStateHome, "Home"},
        {MBIMRegisterStateRoaming, "Roaming"},
        {MBIMRegisterStatePartner, "Partner"},
        {MBIMRegisterStateDenied, "Denied"},
    };
    int idx;

    for (idx = 0; idx < (int)(sizeof(_enumstr) / sizeof(_enumstr[0])); idx++)
    {
        if (_val == _enumstr[idx].val)
            return _enumstr[idx].name;
    }

    return "Undefined";
};

static const char *MBIMRegisterModeStr(int _val)
{
    struct
    {
        int val;
        char *name;
    } _enumstr[] = {
        {MBIMRegisterModeUnknown, "Unknown"},
        {MBIMRegisterModeAutomatic, "Automatic"},
        {MBIMRegisterModeManual, "Manual"},
    };
    int idx;

    for (idx = 0; (int)(sizeof(_enumstr) / sizeof(_enumstr[0])); idx++)
    {
        if (_val == _enumstr[idx].val)
            return _enumstr[idx].name;
    }

    return "Undefined";
};

static const char *MBIMSubscriberReadyStateStr(int _val)
{
    struct
    {
        int val;
        char *name;
    } _enumstr[] = {
        {MBIMSubscriberReadyStateNotInitialized, "NotInitialized"},
        {MBIMSubscriberReadyStateInitialized, "Initialized"},
        {MBIMSubscriberReadyStateSimNotInserted, "NotInserted"},
        {MBIMSubscriberReadyStateBadSim, "BadSim"},
        {MBIMSubscriberReadyStateFailure, "Failure"},
        {MBIMSubscriberReadyStateNotActivated, "NotActivated"},
        {MBIMSubscriberReadyStateDeviceLocked, "DeviceLocked"},
    };
    int idx;

    for (idx = 0; idx < (int)(sizeof(_enumstr) / sizeof(_enumstr[0])); idx++)
    {
        if (_val == _enumstr[idx].val)
            return _enumstr[idx].name;
    }

    return "Undefined";
};

static const char *MBIMDataClassStr(int _val)
{
    struct
    {
        int val;
        char *name;
    } _enumstr[] = {
        {MBIMDataClassNone, "None"},
        {MBIMDataClassGPRS, "GPRS"},
        {MBIMDataClassEDGE, "EDGE"},
        {MBIMDataClassUMTS, "UMTS"},
        {MBIMDataClassHSDPA, "HSDPA"},
        {MBIMDataClassHSUPA, "HSUPA"},
        {MBIMDataClassLTE, "LTE"},
        {MBIMDataClass5G_NSA, "5G_NSA"},
        {MBIMDataClass5G_SA, "5G_SA"},
        {MBIMDataClass1XRTT, "1XRTT"},
        {MBIMDataClass1XEVDO, "1XEVDO"},
        {MBIMDataClass1XEVDORevA, "1XEVDORevA"},
        {MBIMDataClass1XEVDV, "1XEVDV"},
        {MBIMDataClass3XRTT, "3XRTT"},
        {MBIMDataClass1XEVDORevB, "1XEVDORevB"},
        {MBIMDataClassUMB, "UMB"},
        {MBIMDataClassCustom, "Custom"},
    };
    int idx;

    for (idx = 0; idx < (int)(sizeof(_enumstr) / sizeof(_enumstr[0])); idx++)
    {
        if (_val == _enumstr[idx].val)
            return _enumstr[idx].name;
    }

    return "Unknow";
};

static const char *MBIMPacketServiceStateStr(int _val)
{
    struct
    {
        int val;
        char *name;
    } _enumstr[] = {
        {MBIMPacketServiceStateUnknown, "Unknown"},
        {MBIMPacketServiceStateAttaching, "Attaching"},
        {MBIMPacketServiceStateAttached, "Attached"},
        {MBIMPacketServiceStateDetaching, "Detaching"},
        {MBIMPacketServiceStateDetached, "Detached"},
    };
    int idx;

    for (idx = 0; idx < (int)(sizeof(_enumstr) / sizeof(_enumstr[0])); idx++)
    {
        if (_val == _enumstr[idx].val)
            return _enumstr[idx].name;
    }

    return "Undefined";
};

static const char *MBIMContextIPTypeStr(int _val)
{
    struct
    {
        int val;
        char *name;
    } _enumstr[] = {
        {MBIMContextIPTypeDefault, "MBIMContextIPTypeDefault"},
        {MBIMContextIPTypeIPv4, "MBIMContextIPTypeIPv4"},
        {MBIMContextIPTypeIPv6, "MBIMContextIPTypeIPv6"},
        {MBIMContextIPTypeIPv4v6, "MBIMContextIPTypeIPv4v6"},
        {MBIMContextIPTypeIPv4AndIPv6, "MBIMContextIPTypeIPv4AndIPv6"},
    };
    int idx;

    for (idx = 0; idx < (int)(sizeof(_enumstr) / sizeof(_enumstr[0])); idx++)
    {
        if (_val == _enumstr[idx].val)
            return _enumstr[idx].name;
    }

    return "MBIMContextIPTypeUnknow";
};

static const char *MBIMMSGTypeStr(int _val)
{
    struct
    {
        int val;
        char *name;
    } _enumstr[] = {
        {MBIM_OPEN_MSG, "MBIM_OPEN_MSG"},
        {MBIM_CLOSE_MSG, "MBIM_CLOSE_MSG"},
        {MBIM_COMMAND_MSG, "MBIM_COMMAND_MSG"},
        {MBIM_HOST_ERROR_MSG, "MBIM_HOST_ERROR_MSG"},
        {MBIM_OPEN_DONE, "MBIM_OPEN_DONE"},
        {MBIM_CLOSE_DONE, "MBIM_CLOSE_DONE"},
        {MBIM_COMMAND_DONE, "MBIM_COMMAND_DONE"},
        {MBIM_FUNCTION_ERROR_MSG, "MBIM_FUNCTION_ERROR_MSG"},
        {MBIM_INDICATE_STATUS_MSG, "MBIM_INDICATE_STATUS_MSG"},
    };

    return_enumstr(_val, _enumstr);
    return "MBIMMSGTypeUnknow";
};

static const char *CID2Str(const char *uuid, uint32_t CID)
{
    struct
    {
        const char *uuid;
        uint32_t CID;
        const char *name;
    } _enumstr[] =
        {
            {UUID_BASIC_CONNECT, MBIM_CID_DEVICE_CAPS, "MBIM_CID_DEVICE_CAPS"},
            {UUID_BASIC_CONNECT, MBIM_CID_SUBSCRIBER_READY_STATUS, "MBIM_CID_SUBSCRIBER_READY_STATUS"},
            {UUID_BASIC_CONNECT, MBIM_CID_RADIO_STATE, "MBIM_CID_RADIO_STATE"},
            {UUID_BASIC_CONNECT, MBIM_CID_PIN, "MBIM_CID_PIN"},
            {UUID_BASIC_CONNECT, MBIM_CID_PIN_LIS, "MBIM_CID_PIN_LIS"},
            {UUID_BASIC_CONNECT, MBIM_CID_HOME_PROVIDER, "MBIM_CID_HOME_PROVIDER"},
            {UUID_BASIC_CONNECT, MBIM_CID_PREFERRED_PROVIDERS, "MBIM_CID_PREFERRED_PROVIDERS"},
            {UUID_BASIC_CONNECT, MBIM_CID_VISIBLE_PROVIDERS, "MBIM_CID_VISIBLE_PROVIDERS"},
            {UUID_BASIC_CONNECT, MBIM_CID_REGISTER_STATE, "MBIM_CID_REGISTER_STATE"},
            {UUID_BASIC_CONNECT, MBIM_CID_PACKET_SERVICE, "MBIM_CID_PACKET_SERVICE"},
            {UUID_BASIC_CONNECT, MBIM_CID_SIGNAL_STATE, "MBIM_CID_SIGNAL_STATE"},
            {UUID_BASIC_CONNECT, MBIM_CID_CONNECT, "MBIM_CID_CONNECT"},
            {UUID_BASIC_CONNECT, MBIM_CID_PROVISIONED_CONTEXTS, "MBIM_CID_PROVISIONED_CONTEXTS"},
            {UUID_BASIC_CONNECT, MBIM_CID_SERVICE_ACTIVATION, "MBIM_CID_SERVICE_ACTIVATION"},
            {UUID_BASIC_CONNECT, MBIM_CID_IP_CONFIGURATION, "MBIM_CID_IP_CONFIGURATION"},
            {UUID_BASIC_CONNECT, MBIM_CID_DEVICE_SERVICES, "MBIM_CID_DEVICE_SERVICES"},
            {UUID_BASIC_CONNECT, MBIM_CID_DEVICE_SERVICE_SUBSCRIBE_LIST, "MBIM_CID_DEVICE_SERVICE_SUBSCRIBE_LIST"},
            {UUID_BASIC_CONNECT, MBIM_CID_PACKET_STATISTICS, "MBIM_CID_PACKET_STATISTICS"},
            {UUID_BASIC_CONNECT, MBIM_CID_NETWORK_IDLE_HINT, "MBIM_CID_NETWORK_IDLE_HINT"},
            {UUID_BASIC_CONNECT, MBIM_CID_EMERGENCY_MODE, "MBIM_CID_EMERGENCY_MODE"},
            {UUID_BASIC_CONNECT, MBIM_CID_IP_PACKET_FILTERS, "MBIM_CID_IP_PACKET_FILTERS"},
            {UUID_BASIC_CONNECT, MBIM_CID_MULTICARRIER_PROVIDERS, "MBIM_CID_MULTICARRIER_PROVIDERS"},

            {UUID_BASIC_CONNECT_EXT, MBIM_CID_MS_PROVISIONED_CONTEXT_V2, "MBIM_CID_MS_PROVISIONED_CONTEXT_V2"},
            {UUID_BASIC_CONNECT_EXT, MBIM_CID_MS_NETWORK_BLACKLIST, "MBIM_CID_MS_NETWORK_BLACKL     IST"},
            {UUID_BASIC_CONNECT_EXT, MBIM_CID_MS_LTE_ATTACH_CONFIG, "MBIM_CID_MS_LTE_ATTACH_CONFIG"},
            {UUID_BASIC_CONNECT_EXT, MBIM_CID_MS_LTE_ATTACH_STATUS, "MBIM_CID_MS_LTE_ATTACH_STATUS"},
            {UUID_BASIC_CONNECT_EXT, MBIM_CID_MS_SYS_CAPS, "MBIM_CID_MS_SYS_CAPS"},
            {UUID_BASIC_CONNECT_EXT, MBIM_CID_MS_DEVICE_CAPS_V2, "MBIM_     CID_MS_DEVICE_CAPS_V2"},
            {UUID_BASIC_CONNECT_EXT, MBIM_CID_MS_DEVICE_SLOT_MAPPING, "MBIM_CID_MS_DEVICE_SLOT_MAPPING"},
            {UUID_BASIC_CONNECT_EXT, MBIM_CID_MS_SLOT_INFO_STATUS, "MBIM_CID_MS_SLOT_INFO_STATUS"},
            {UUID_BASIC_CONNECT_EXT, MBIM_CID_MS_PCO, "MBIM_CID_MS_PCO"},
            {UUID_BASIC_CONNECT_EXT, MBIM_CID_MS_DEVICE_RESET, "MBIM_CID_MS_DEVICE_RESET"},
            {UUID_BASIC_CONNECT_EXT, MBIM_CID_MS_BASE_STATIONS_INFO, "MBIM_CID_MS_BASE_STATIONS_INFO"},
            {UUID_BASIC_CONNECT_EXT, MBIM_CID_MS_LOCATION_INFO_STATUS, "MBIM_CID_MS_LOCATION_INFO_STATUS"},
            {UUID_BASIC_CONNECT_EXT, MBIM_CID_NOT_DEFINED, "MBIM_CID_NOT_DEFINED"},
            {UUID_BASIC_CONNECT_EXT, MBIM_CID_MS_PIN_EX, "MBIM_CID_MS_PIN_EX"},
            {UUID_BASIC_CONNECT_EXT, MBIM_CID_MS_VERSION, "MBIM_CID_MS_VERSION"},

            {UUID_LIBMBIM_PROXY, MBIM_CID_PROXY_CONTROL_UNKNOWN, "MBIM_CID_PROXY_CONTROL_UNKNOWN"},
            {UUID_LIBMBIM_PROXY, MBIM_CID_PROXY_CONTROL_CONFIGURATION, "MBIM_CID_PROXY_CONTROL_CONFIGURATION"},

            {uuid_qmbe, QBI_SVC_QMBE_MBIM_CID_DIAG_CONFIG, "QBI_SVC_QMBE_MBIM_CID_DIAG_CONFIG"},
            {uuid_qmbe, QBI_SVC_QMBE_MBIM_CID_DIAG_DATA, "QBI_SVC_QMBE_MBIM_CID_DIAG_DATA"},
            {uuid_qmbe, QUECTEL_QBI_SVC_QMBE_MBIM_CID_DIAG_OVER_MBIM_CFG, "QUECTEL_QBI_SVC_QMBE_MBIM_CID_DIAG_OVER_MBIM_CFG"},
        };
    int idx;

    for (idx = 0; idx < (int)(sizeof(_enumstr) / sizeof(_enumstr[0])); idx++)
    {
        if (!strcmp(uuid, _enumstr[idx].uuid) && CID == _enumstr[idx].CID)
            return _enumstr[idx].name;
    }

    return "Unknow";
};

static void mbim_dump_uuid_and_cid(UUID_T *pDeviceServiceId, uint32_t CID, const char *direction)
{
    const char *uuid = uuid2str(pDeviceServiceId);

    mbim_debug("%s DeviceServiceId = %s (%s)", direction, DeviceServiceId2str(pDeviceServiceId), uuid);
    mbim_debug("%s CID = %s (%u)", direction, CID2Str(uuid, le32toh(CID)), le32toh(CID));
}

static void mbim_dump_header(MBIM_MESSAGE_HEADER *pMsg, const char *direction)
{
    mbim_debug("%s Header:", direction);
    mbim_debug("%s MessageLength = %u", direction, le32toh(pMsg->MessageLength));
    mbim_debug("%s MessageType =  %s (0x%08x)", direction, MBIMMSGTypeStr(le32toh(pMsg->MessageType)), le32toh(pMsg->MessageType));
    mbim_debug("%s TransactionId = %u", direction, le32toh(pMsg->TransactionId));
    mbim_debug("%s Contents:", direction);
}

static void mbim_dump_command_msg(MBIM_COMMAND_MSG_T *pCmdMsg, const char *direction)
{
    mbim_dump_uuid_and_cid(&pCmdMsg->DeviceServiceId, pCmdMsg->CID, direction);
    mbim_debug("%s CommandType = %s (%u)", direction, le32toh(pCmdMsg->CommandType) ? "set" : "query", le32toh(pCmdMsg->CommandType));
    mbim_debug("%s InformationBufferLength = %u", direction, le32toh(pCmdMsg->InformationBufferLength));
}

static void mbim_dump_command_done(MBIM_COMMAND_DONE_T *pCmdDone, const char *direction)
{
    mbim_dump_uuid_and_cid(&pCmdDone->DeviceServiceId, pCmdDone->CID, direction);
    mbim_debug("%s Status = %u", direction, le32toh(pCmdDone->Status));
    mbim_debug("%s InformationBufferLength = %u", direction, le32toh(pCmdDone->InformationBufferLength));
}

static void mbim_dump_indicate_msg(MBIM_INDICATE_STATUS_MSG_T *pIndMsg, const char *direction)
{
    mbim_dump_uuid_and_cid(&pIndMsg->DeviceServiceId, pIndMsg->CID, direction);
    mbim_debug("%s InformationBufferLength = %u", direction, le32toh(pIndMsg->InformationBufferLength));
}

static void mbim_dump_connect(MBIM_CONNECT_T *pInfo, const char *direction)
{
    mbim_debug("%s SessionId = %u", direction, le32toh(pInfo->SessionId));
    mbim_debug("%s ActivationState = %s (%u)", direction, MBIMActivationStateStr(le32toh(pInfo->ActivationState)), le32toh(pInfo->ActivationState));
    mbim_debug("%s IPType = %s", direction, MBIMContextIPTypeStr(le32toh(pInfo->IPType)));
    mbim_debug("%s VoiceCallState = %s", direction, MBIMVoiceCallStateStr(le32toh(pInfo->VoiceCallState)));
    mbim_debug("%s ContextType = %s", direction, uuid2str(&pInfo->ContextType));
    mbim_debug("%s NwError = %u", direction, le32toh(pInfo->NwError));
}

static void mbim_dump_signal_state(MBIM_SIGNAL_STATE_INFO_T *pInfo, const char *direction)
{
    mbim_debug("%s Rssi = %u", direction, le32toh(pInfo->Rssi));
    mbim_debug("%s ErrorRate = %u", direction, le32toh(pInfo->ErrorRate));
    mbim_debug("%s SignalStrengthInterval = %u", direction, le32toh(pInfo->SignalStrengthInterval));
    mbim_debug("%s RssiThreshold = %u", direction, le32toh(pInfo->RssiThreshold));
    mbim_debug("%s ErrorRateThreshold = %u", direction, le32toh(pInfo->ErrorRateThreshold));
}

static void mbim_dump_packet_service(MBIM_PACKET_SERVICE_INFO_T *pInfo, const char *direction)
{
    mbim_debug("%s NwError = %u", direction, le32toh(pInfo->NwError));
    mbim_debug("%s PacketServiceState = %s", direction, MBIMPacketServiceStateStr(le32toh(pInfo->PacketServiceState)));
    mbim_debug("%s HighestAvailableDataClass = %s", direction, MBIMDataClassStr(le32toh(pInfo->HighestAvailableDataClass)));
    mbim_debug("%s UplinkSpeed = %ld", direction, (long)le64toh(pInfo->UplinkSpeed));
    mbim_debug("%s DownlinkSpeed = %ld", direction, (long)le64toh(pInfo->DownlinkSpeed));
}

static void mbim_dump_subscriber_status(MBIM_SUBSCRIBER_READY_STATUS_T *pInfo, const char *direction)
{
    mbim_debug("%s ReadyState = %s", direction, MBIMSubscriberReadyStateStr(le32toh(pInfo->ReadyState)));
    mbim_debug("%s SIMICCID = %s", direction, mbim_get_segment(pInfo, le32toh(pInfo->SimIccIdOffset), le32toh(pInfo->SimIccIdSize)));
    mbim_debug("%s SubscriberID = %s", direction, mbim_get_segment(pInfo, le32toh(pInfo->SubscriberIdOffset), le32toh(pInfo->SubscriberIdSize)));
    /* maybe more than one number */
    uint32_t idx;
    for (idx = 0; idx < le32toh(pInfo->ElementCount); idx++)
    {
        uint32_t offset = ((uint32_t *)((uint8_t *)pInfo + offsetof(MBIM_SUBSCRIBER_READY_STATUS_T, TelephoneNumbersRefList)))[0];
        uint32_t length = ((uint32_t *)((uint8_t *)pInfo + offsetof(MBIM_SUBSCRIBER_READY_STATUS_T, TelephoneNumbersRefList)))[1];
        mbim_debug("%s Number = %s", direction, mbim_get_segment(pInfo, le32toh(offset), le32toh(length)));
    }
}

static void mbim_dump_regiester_status(MBIM_REGISTRATION_STATE_INFO_T *pInfo, const char *direction)
{
    mbim_debug("%s NwError = %u", direction, le32toh(pInfo->NwError));
    mbim_debug("%s RegisterState = %s", direction, MBIMRegisterStateStr(le32toh(pInfo->RegisterState)));
    mbim_debug("%s RegisterMode = %s", direction, MBIMRegisterModeStr(le32toh(pInfo->RegisterMode)));
}

static void mbim_dump_ipconfig(MBIM_IP_CONFIGURATION_INFO_T *pInfo, const char *direction)
{
    uint8_t prefix = 0, *ipv4 = NULL, *ipv6 = NULL, *gw = NULL, *dns1 = NULL, *dns2 = NULL;

    mbim_debug("%s SessionId = %u", direction, le32toh(pInfo->SessionId));
    mbim_debug("%s IPv4ConfigurationAvailable = 0x%x", direction, le32toh(pInfo->IPv4ConfigurationAvailable));
    mbim_debug("%s IPv6ConfigurationAvailable = 0x%x", direction, le32toh(pInfo->IPv6ConfigurationAvailable));
    mbim_debug("%s IPv4AddressCount = 0x%x", direction, le32toh(pInfo->IPv4AddressCount));
    mbim_debug("%s IPv4AddressOffset = 0x%x", direction, le32toh(pInfo->IPv4AddressOffset));
    mbim_debug("%s IPv6AddressCount = 0x%x", direction, le32toh(pInfo->IPv6AddressCount));
    mbim_debug("%s IPv6AddressOffset = 0x%x", direction, le32toh(pInfo->IPv6AddressOffset));

    /* IPv4 */
    if (le32toh(pInfo->IPv4ConfigurationAvailable) & 0x1)
    {
        MBIM_IPV4_ELEMENT_T *pAddress = (MBIM_IPV4_ELEMENT_T *)(&pInfo->DataBuffer[le32toh(pInfo->IPv4AddressOffset) - sizeof(MBIM_IP_CONFIGURATION_INFO_T)]);
        prefix = le32toh(pAddress->OnLinkPrefixLength);
        ipv4 = pAddress->IPv4Address;
        mbim_debug("%s IPv4 = %u.%u.%u.%u/%u", direction, ipv4[0], ipv4[1], ipv4[2], ipv4[3], prefix);
    }
    if (le32toh(pInfo->IPv4ConfigurationAvailable) & 0x2)
    {
        gw = (uint8_t *)(&pInfo->DataBuffer[le32toh(pInfo->IPv4GatewayOffset) - sizeof(MBIM_IP_CONFIGURATION_INFO_T)]);
        mbim_debug("%s gw = %u.%u.%u.%u", direction, gw[0], gw[1], gw[2], gw[3]);
    }
    if (le32toh(pInfo->IPv4ConfigurationAvailable) & 0x3)
    {
        dns1 = (uint8_t *)(&pInfo->DataBuffer[le32toh(pInfo->IPv4DnsServerOffset) - sizeof(MBIM_IP_CONFIGURATION_INFO_T)]);
        mbim_debug("%s dns1 = %u.%u.%u.%u", direction, dns1[0], dns1[1], dns1[2], dns1[3]);
        if (le32toh(pInfo->IPv4DnsServerCount) == 2)
        {
            dns2 = dns1 + 4;
            mbim_debug("%s dns2 = %u.%u.%u.%u", direction, dns2[0], dns2[1], dns2[2], dns2[3]);
        }
    }
    if (le32toh(pInfo->IPv4Mtu))
        mbim_debug("%s ipv4 mtu = %u", direction, le32toh(pInfo->IPv4Mtu));

    /* IPv6 */
    if (le32toh(pInfo->IPv6ConfigurationAvailable) & 0x1)
    {
        MBIM_IPV6_ELEMENT_T *pAddress = (MBIM_IPV6_ELEMENT_T *)(&pInfo->DataBuffer[le32toh(pInfo->IPv6AddressOffset) - sizeof(MBIM_IP_CONFIGURATION_INFO_T)]);
        prefix = le32toh(pAddress->OnLinkPrefixLength);
        ipv6 = pAddress->IPv6Address;
        mbim_debug("%s IPv6 = %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x/%d",
                   direction, ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6], ipv6[7],
                   ipv6[8], ipv6[9], ipv6[10], ipv6[11], ipv6[12], ipv6[13], ipv6[14], ipv6[15], prefix);
    }
    if (le32toh(pInfo->IPv6ConfigurationAvailable) & 0x2)
    {
        gw = (uint8_t *)(&pInfo->DataBuffer[le32toh(pInfo->IPv6GatewayOffset) - sizeof(MBIM_IP_CONFIGURATION_INFO_T)]);
        mbim_debug("%s gw = %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                   direction, gw[0], gw[1], gw[2], gw[3], gw[4], gw[5], gw[6], gw[7],
                   gw[8], gw[9], gw[10], gw[11], gw[12], gw[13], gw[14], gw[15]);
    }
    if (le32toh(pInfo->IPv6ConfigurationAvailable) & 0x3)
    {
        dns1 = (uint8_t *)(&pInfo->DataBuffer[le32toh(pInfo->IPv6DnsServerOffset) - sizeof(MBIM_IP_CONFIGURATION_INFO_T)]);
        mbim_debug("%s dns1 = %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                   direction, dns1[0], dns1[1], dns1[2], dns1[3], dns1[4], dns1[5], dns1[6], dns1[7],
                   dns1[8], dns1[9], dns1[10], dns1[11], dns1[12], dns1[13], dns1[14], dns1[15]);
        if (le32toh(pInfo->IPv6DnsServerCount) == 2)
        {
            dns2 = dns1 + 16;
            mbim_debug("%s dns2 = %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                       direction, dns2[0], dns2[1], dns2[2], dns2[3], dns1[4], dns1[5], dns1[6], dns1[7],
                       dns2[8], dns2[9], dns2[10], dns2[11], dns2[12], dns2[13], dns2[14], dns2[15]);
        }
    }
    if (le32toh(pInfo->IPv6Mtu))
        mbim_debug("%s ipv6 mtu = %u", direction, le32toh(pInfo->IPv6Mtu));
}

void mbim_dump(MBIM_MESSAGE_HEADER *pMsg, int mbim_verbose)
{
    unsigned char *data = (unsigned char *)pMsg;
    const char *direction = (pMsg->MessageType & 0x80000000) ? "<" : ">";

    if (!mbim_verbose)
        return;

    if (mbim_verbose)
    {
        unsigned i;
        static char _tmp[4096 * 3 + 12] = {'\0'};
        _tmp[0] = (le32toh(pMsg->MessageType) & 0x80000000) ? '<' : '>';
        _tmp[1] = ' ';
        _tmp[2] = '\0';
        for (i = 0; i < le32toh(pMsg->MessageLength) && i < 4096; i++)
            snprintf(_tmp + strlen(_tmp), 4096 - strlen(_tmp), "%02X:", data[i]);
        mbim_debug("%s", _tmp);
    }

    mbim_dump_header(pMsg, direction);

    switch (le32toh(pMsg->MessageType))
    {
    case MBIM_OPEN_MSG:
    {
        MBIM_OPEN_MSG_T *pOpenMsg = (MBIM_OPEN_MSG_T *)pMsg;
        mbim_debug("%s MaxControlTransfer = %u", direction, le32toh(pOpenMsg->MaxControlTransfer));
    }
    break;
    case MBIM_OPEN_DONE:
    {
        MBIM_OPEN_DONE_T *pOpenDone = (MBIM_OPEN_DONE_T *)pMsg;
        mbim_debug("%s Status = %u", direction, le32toh(pOpenDone->Status));
    }
    break;
    case MBIM_CLOSE_MSG:
    {
    }
    break;
    case MBIM_CLOSE_DONE:
    {
        MBIM_CLOSE_DONE_T *pCloseDone = (MBIM_CLOSE_DONE_T *)pMsg;
        mbim_debug("%s Status = %u", direction, le32toh(pCloseDone->Status));
    }
    break;
    case MBIM_COMMAND_MSG:
    {
        MBIM_COMMAND_MSG_T *pCmdMsg = (MBIM_COMMAND_MSG_T *)pMsg;

        mbim_dump_command_msg(pCmdMsg, direction);
        if (!mbim_uuid_cmp(pCmdMsg->DeviceServiceId.uuid, UUID_BASIC_CONNECT))
        {
            switch (le32toh(pCmdMsg->CID))
            {
            case MBIM_CID_CONNECT:
            {
                MBIM_SET_CONNECT_T *pInfo = (MBIM_SET_CONNECT_T *)pCmdMsg->InformationBuffer;
                mbim_debug("%s SessionId = %u", direction, le32toh(pInfo->SessionId));
            }
            break;
            case MBIM_CID_IP_CONFIGURATION:
            {
                MBIM_IP_CONFIGURATION_INFO_T *pInfo = (MBIM_IP_CONFIGURATION_INFO_T *)pCmdMsg->InformationBuffer;
                mbim_debug("%s SessionId = %u", direction, le32toh(pInfo->SessionId));
            }
            break;
            default:
                break;
            }
        }
    }
    break;
    case MBIM_COMMAND_DONE:
    {
        MBIM_COMMAND_DONE_T *pCmdDone = (MBIM_COMMAND_DONE_T *)pMsg;

        mbim_dump_command_done(pCmdDone, direction);
        if (le32toh(pCmdDone->InformationBufferLength) == 0)
            return;

        if (!mbim_uuid_cmp(pCmdDone->DeviceServiceId.uuid, UUID_BASIC_CONNECT))
        {
            switch (le32toh(pCmdDone->CID))
            {
            case MBIM_CID_CONNECT:
            {
                MBIM_CONNECT_T *pInfo = (MBIM_CONNECT_T *)pCmdDone->InformationBuffer;
                mbim_dump_connect(pInfo, direction);
            }
            break;
            case MBIM_CID_IP_CONFIGURATION:
            {
                MBIM_IP_CONFIGURATION_INFO_T *pInfo = (MBIM_IP_CONFIGURATION_INFO_T *)pCmdDone->InformationBuffer;
                mbim_dump_ipconfig(pInfo, direction);
            }
            break;
            case MBIM_CID_PACKET_SERVICE:
            {
                MBIM_PACKET_SERVICE_INFO_T *pInfo = (MBIM_PACKET_SERVICE_INFO_T *)pCmdDone->InformationBuffer;
                mbim_dump_packet_service(pInfo, direction);
            }
            break;
            case MBIM_CID_SUBSCRIBER_READY_STATUS:
            {
                MBIM_SUBSCRIBER_READY_STATUS_T *pInfo = (MBIM_SUBSCRIBER_READY_STATUS_T *)pCmdDone->InformationBuffer;
                mbim_dump_subscriber_status(pInfo, direction);
            }
            break;
            case MBIM_CID_REGISTER_STATE:
            {
                MBIM_REGISTRATION_STATE_INFO_T *pInfo = (MBIM_REGISTRATION_STATE_INFO_T *)pCmdDone->InformationBuffer;
                mbim_dump_regiester_status(pInfo, direction);
            }
            break;
            default:
                break;
            }
        }
    }
    break;
    case MBIM_INDICATE_STATUS_MSG:
    {
        MBIM_INDICATE_STATUS_MSG_T *pIndMsg = (MBIM_INDICATE_STATUS_MSG_T *)pMsg;

        mbim_dump_indicate_msg(pIndMsg, direction);
        if (le32toh(pIndMsg->InformationBufferLength) == 0)
            return;

        if (!mbim_uuid_cmp(pIndMsg->DeviceServiceId.uuid, UUID_BASIC_CONNECT))
        {
            switch (le32toh(pIndMsg->CID))
            {
            case MBIM_CID_CONNECT:
            {
                MBIM_CONNECT_T *pInfo = (MBIM_CONNECT_T *)pIndMsg->InformationBuffer;
                mbim_dump_connect(pInfo, direction);
            }
            break;
            case MBIM_CID_SIGNAL_STATE:
            {
                MBIM_SIGNAL_STATE_INFO_T *pInfo = (MBIM_SIGNAL_STATE_INFO_T *)pIndMsg->InformationBuffer;
                mbim_dump_signal_state(pInfo, direction);
            }
            break;
            case MBIM_CID_SUBSCRIBER_READY_STATUS:
            {
                MBIM_SUBSCRIBER_READY_STATUS_T *pInfo = (MBIM_SUBSCRIBER_READY_STATUS_T *)pIndMsg->InformationBuffer;
                mbim_dump_subscriber_status(pInfo, direction);
            }
            break;
            case MBIM_CID_REGISTER_STATE:
            {
                MBIM_REGISTRATION_STATE_INFO_T *pInfo = (MBIM_REGISTRATION_STATE_INFO_T *)pIndMsg->InformationBuffer;
                mbim_dump_regiester_status(pInfo, direction);
            }
            break;
            case MBIM_CID_PACKET_SERVICE:
            {
                MBIM_PACKET_SERVICE_INFO_T *pInfo = (MBIM_PACKET_SERVICE_INFO_T *)pIndMsg->InformationBuffer;
                mbim_dump_packet_service(pInfo, direction);
            }
            break;
            default:
                break;
            }
        }
        else if (!mbim_uuid_cmp(pIndMsg->DeviceServiceId.uuid, UUID_BASIC_CONNECT_EXT))
        {
        }
    }
    break;
    case MBIM_FUNCTION_ERROR_MSG:
    {
        MBIM_FUNCTION_ERROR_MSG_T *pErrMsg = (MBIM_FUNCTION_ERROR_MSG_T *)pMsg;
        mbim_debug("%s ErrorStatusCode = %u", direction, le32toh(pErrMsg->ErrorStatusCode));
    }
    break;
    default:
        break;
    }
}
