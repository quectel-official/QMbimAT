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

#include <inttypes.h>

#define UUID_BASIC_CONNECT "a289cc33-bcbb-8b4f-b6b0-133ec2aae6df"
// https://docs.microsoft.com/en-us/windows-hardware/drivers/network/mb-5g-data-class-support
#define UUID_BASIC_CONNECT_EXT "3d01dcc5-fef5-4d05-0d3a-bef7058e9aaf"
#define UUID_SMS "533fbeeb-14fe-4467-9f90-33a223e56c3f"
#define UUID_USSD "e550a0c8-5e82-479e-82f7-10abf4c3351f"
#define UUID_PHONEBOOK "4bf38476-1e6a-41db-b1d8-bed289c25bdb"
#define UUID_STK "d8f20131-fcb5-4e17-8602-d6ed3816164c"
#define UUID_AUTH "1d2b5ff7-0aa1-48b2-aa52-50f15767174e"
#define UUID_DSS "c08a26dd-7718-4382-8482-6e0d583c4d0e"
#define uuid_ext_qmux "d1a30bc2-f97a-6e43-bf65-c7e24fb0f0d3"
#define uuid_mshsd "883b7c26-985f-43fa-9804-27d7fb80959c"
#define uuid_qmbe "2d0c12c9-0e6a-495a-915c-8d174fe5d63c"
#define UUID_MSFWID "e9f7dea2-feaf-4009-93ce-90a3694103b6"
#define uuid_atds "5967bdcc-7fd2-49a2-9f5c-b2e70e527db3"
#define uuid_qdu "6427015f-579d-48f5-8c54-f43ed1e76f83"
#define UUID_MS_UICC_LOW_LEVEL "c2f6588e-f037-4bc9-8665-f4d44bd09367"
#define UUID_MS_SARControl "68223D04-9F6C-4E0F-822D-28441FB72340"
#define UUID_VOICEEXTENSIONS "8d8b9eba-37be-449b-8f1e-61cb034a702e"
#define UUID_MBIMContextTypeInternet "7E5E2A7E-4E6F-7272-736B-656E7E5E2A7E"
#define UUID_LIBMBIM_PROXY "838cf7fb-8d0d-4d7f-871e-d71dbefbb39b"
#define UUID_QUECTEL "11223344-5566-7788-99aa-bbccddeeff11"

#pragma pack(4)

typedef enum
{
    MBIM_CID_CMD_TYPE_QUERY = 0,
    MBIM_CID_CMD_TYPE_SET = 1,
} MBIM_CID_CMD_TYPE_E;

typedef enum
{
    MBIM_CID_DEVICE_CAPS = 1,
    MBIM_CID_SUBSCRIBER_READY_STATUS = 2,
    MBIM_CID_RADIO_STATE = 3,
    MBIM_CID_PIN = 4,
    MBIM_CID_PIN_LIS = 5,
    MBIM_CID_HOME_PROVIDER = 6,
    MBIM_CID_PREFERRED_PROVIDERS = 7,
    MBIM_CID_VISIBLE_PROVIDERS = 8,
    MBIM_CID_REGISTER_STATE = 9,
    MBIM_CID_PACKET_SERVICE = 10,
    MBIM_CID_SIGNAL_STATE = 11,
    MBIM_CID_CONNECT = 12,
    MBIM_CID_PROVISIONED_CONTEXTS = 13,
    MBIM_CID_SERVICE_ACTIVATION = 14,
    MBIM_CID_IP_CONFIGURATION = 15,
    MBIM_CID_DEVICE_SERVICES = 16,
    MBIM_CID_DEVICE_SERVICE_SUBSCRIBE_LIST = 19,
    MBIM_CID_PACKET_STATISTICS = 20,
    MBIM_CID_NETWORK_IDLE_HINT = 21,
    MBIM_CID_EMERGENCY_MODE = 22,
    MBIM_CID_IP_PACKET_FILTERS = 23,
    MBIM_CID_MULTICARRIER_PROVIDERS = 24,
} UUID_BASIC_CONNECT_CID_E;

typedef enum
{
    MBIM_CID_MS_PROVISIONED_CONTEXT_V2 = 1,
    MBIM_CID_MS_NETWORK_BLACKLIST = 2,
    MBIM_CID_MS_LTE_ATTACH_CONFIG = 3,
    MBIM_CID_MS_LTE_ATTACH_STATUS = 4,
    MBIM_CID_MS_SYS_CAPS = 5,
    MBIM_CID_MS_DEVICE_CAPS_V2 = 6,
    MBIM_CID_MS_DEVICE_SLOT_MAPPING = 7,
    MBIM_CID_MS_SLOT_INFO_STATUS = 8,
    MBIM_CID_MS_PCO = 9,
    MBIM_CID_MS_DEVICE_RESET = 10,
    MBIM_CID_MS_BASE_STATIONS_INFO = 11,
    MBIM_CID_MS_LOCATION_INFO_STATUS = 12,
    MBIM_CID_NOT_DEFINED = 13,
    MBIM_CID_MS_PIN_EX = 14,
    MBIM_CID_MS_VERSION = 15,
} UUID_BASIC_CONNECT_EXT_CID_E;

typedef enum
{
    MBIM_CID_SMS_CONFIGURATION = 1,        // Y Y Y
    MBIM_CID_SMS_READ = 2,                 // N Y Y
    MBIM_CID_SMS_SEND = 3,                 // Y N N
    MBIM_CID_SMS_DELETE = 4,               // Y N N
    MBIM_CID_SMS_MESSAGE_STORE_STATUS = 5, // N Y Y
} UUID_SMS_CID_E;

typedef enum
{
    MBIM_CID_DSS_CONNECT = 1, // Y N N
} UUID_DSS_CID_E;

typedef enum
{
    MBIM_CID_MS_SAR_CONFIG = 1, // Y N N
    MBIM_CID_MS_TRANSMISSION_STATUS = 2,
} UUID_MS_SAR_CID_E;

typedef enum
{
    QBI_SVC_QMBE_CID_MIN = 0,

    QBI_SVC_QMBE_MBIM_CID_DIAG_CONFIG = 1,
    QBI_SVC_QMBE_MBIM_CID_DIAG_DATA = 2,

    QUECTEL_QBI_SVC_QMBE_MBIM_CID_DIAG_OVER_MBIM_CFG = 21,
    QUECTEL_QBI_SVC_QMBE_MBIM_CID_MD5 = 22,
    QUECTEL_QBI_SVC_QMBE_MBIM_CID_REBOOT = 23,
    QUECTEL_QBI_SVC_QMBE_MBIM_CID_DELETE = 24,
    QUECTEL_QBI_SVC_QMBE_MBIM_CID_DIAG_DATA = 25,

    QBI_SVC_QMBE_CID_MAX
} qbi_svc_qmbe_cid_e;

typedef enum
{ /*< since=1.10 >*/
  MBIM_CID_PROXY_CONTROL_UNKNOWN = 0,
  MBIM_CID_PROXY_CONTROL_CONFIGURATION = 1
} UUID_LIBMBIM_PROXY_CID_E;

typedef enum
{
    MBIM_OPEN_MSG = 1,
    MBIM_CLOSE_MSG = 2,
    MBIM_COMMAND_MSG = 3,
    MBIM_HOST_ERROR_MSG = 4,
    MBIM_OPEN_DONE = 0x80000001,
    MBIM_CLOSE_DONE = 0x80000002,
    MBIM_COMMAND_DONE = 0x80000003,
    MBIM_FUNCTION_ERROR_MSG = 0x80000004,
    MBIM_INDICATE_STATUS_MSG = 0x80000007,
} MBIM_MSG_Type_E;

typedef enum
{
    MBIM_ERROR_NONE = 0,
    MBIM_ERROR_TIMEOUT_FRAGMENT = 1,
    MBIM_ERROR_FRAGMENT_OUT_OF_SEQUENCE = 2,
    MBIM_ERROR_LENGTH_MISMATCH = 3,
    MBIM_ERROR_DUPLICATED_TID = 4,
    MBIM_ERROR_NOT_OPENED = 5,
    MBIM_ERROR_UNKNOWN = 6,
    MBIM_ERROR_CANCEL = 7,
    MBIM_ERROR_MAX_TRANSFER = 8,
    MBIM_ERROR_MAX
} MBIM_ERROR_E;

typedef enum
{
    MBIM_STATUS_SUCCESS = 0,
    MBIM_STATUS_BUSY = 1,
    MBIM_STATUS_FAILURE = 2,
    MBIM_STATUS_SIM_NOT_INSERTED = 3,
    MBIM_STATUS_BAD_SIM = 4,
    MBIM_STATUS_PIN_REQUIRED = 5,
    MBIM_STATUS_PIN_DISABLED = 6,
    MBIM_STATUS_NOT_REGISTERED = 7,
    MBIM_STATUS_PROVIDERS_NOT_FOUND = 8,
    MBIM_STATUS_NO_DEVICE_SUPPORT = 9,
    MBIM_STATUS_PROVIDER_NOT_VISIBLE = 10,
    MBIM_STATUS_DATA_CLASS_NOT_AVAILABL = 11,
    MBIM_STATUS_PACKET_SERVICE_DETACHED = 12,
    MBIM_STATUS_MAX
} MBIM_STATUS_CODES_E;

typedef enum
{
    MBIMPacketServiceActionAttach = 0,
    MBIMPacketServiceActionDetach = 1,
} MBIM_PACKET_SERVICE_ACTION_E;

typedef enum
{
    MBIMPacketServiceStateUnknown = 0,
    MBIMPacketServiceStateAttaching = 1,
    MBIMPacketServiceStateAttached = 2,
    MBIMPacketServiceStateDetaching = 3,
    MBIMPacketServiceStateDetached = 4,
} MBIM_PACKET_SERVICE_STATE_E;

typedef enum
{
    MBIMDataClassNone = 0x0,
    MBIMDataClassGPRS = 0x1,
    MBIMDataClassEDGE = 0x2,
    MBIMDataClassUMTS = 0x4,
    MBIMDataClassHSDPA = 0x8,
    MBIMDataClassHSUPA = 0x10,
    MBIMDataClassLTE = 0x20,
    MBIMDataClass5G_NSA = 0x40,
    MBIMDataClass5G_SA = 0x80,
    MBIMDataClass1XRTT = 0x10000,
    MBIMDataClass1XEVDO = 0x20000,
    MBIMDataClass1XEVDORevA = 0x40000,
    MBIMDataClass1XEVDV = 0x80000,
    MBIMDataClass3XRTT = 0x100000,
    MBIMDataClass1XEVDORevB = 0x200000,
    MBIMDataClassUMB = 0x400000,
    MBIMDataClassCustom = 0x80000000,
} MBIM_DATA_CLASS_E;

typedef struct
{
    uint32_t NwError;
    uint32_t PacketServiceState;        // MBIM_PACKET_SERVICE_STATE_E
    uint32_t HighestAvailableDataClass; // MBIM_DATA_CLASS_E
    uint64_t UplinkSpeed;
    uint64_t DownlinkSpeed;
} MBIM_PACKET_SERVICE_INFO_T;

typedef struct
{
    uint32_t NwError;
    uint32_t PacketServiceState; // MBIM_PACKET_SERVICE_STATE_E
    uint32_t CurrentDataClass;   // MBIM_DATA_CLASS_E
    uint64_t UplinkSpeed;
    uint64_t DownlinkSpeed;
    uint32_t FrequencyRange;
} MBIM_PACKET_SERVICE_INFO_V2_T;

typedef enum
{
    MBIMSubscriberReadyStateNotInitialized = 0,
    MBIMSubscriberReadyStateInitialized = 1,
    MBIMSubscriberReadyStateSimNotInserted = 2,
    MBIMSubscriberReadyStateBadSim = 3,
    MBIMSubscriberReadyStateFailure = 4,
    MBIMSubscriberReadyStateNotActivated = 5,
    MBIMSubscriberReadyStateDeviceLocked = 6,
} MBIM_SUBSCRIBER_READY_STATE_E;

typedef struct
{
    uint32_t DeviceType;    // MBIM_DEVICE_TYPE
    uint32_t CellularClass; // MBIM_CELLULAR_CLASS
    uint32_t VoiceClass;    // MBIM_VOICE_CLASS
    uint32_t SimClass;      // MBIM_SIM_CLASS
    uint32_t DataClass;     // MBIM_DATA_CLASS
    uint32_t SmsCaps;       // MBIM_SMS_CAPS
    uint32_t ControlCaps;   // MBIM_CTRL_CAPS
    uint32_t MaxSessions;
    uint32_t CustomDataClassOffset;
    uint32_t CustomDataClassSize;
    uint32_t DeviceIdOffset;
    uint32_t DeviceIdSize;
    uint32_t FirmwareInfoOffset;
    uint32_t FirmwareInfoSize;
    uint32_t HardwareInfoOffset;
    uint32_t HardwareInfoSize;
    uint8_t DataBuffer[0]; // DeviceId FirmwareInfo HardwareInfo
} MBIM_DEVICE_CAPS_INFO_T;

typedef enum
{
    MBIMRadioOff = 0,
    MBIMRadioOn = 1,
} MBIM_RADIO_SWITCH_STATE_E;

typedef struct
{
    MBIM_RADIO_SWITCH_STATE_E RadioState;
} MBIM_SET_RADIO_STATE_T;

typedef struct
{
    MBIM_RADIO_SWITCH_STATE_E HwRadioState; // The state of the W_DISABLE switch
    MBIM_RADIO_SWITCH_STATE_E SwRadioState;
} MBIM_RADIO_STATE_INFO_T;

typedef enum
{
    MBIMReadyInfoFlagsNone,
    MBIMReadyInfoFlagsProtectUniqueID,
} MBIM_UNIQUE_ID_FLAGS;

typedef struct
{
    uint32_t ReadyState;
    uint32_t SubscriberIdOffset;
    uint32_t SubscriberIdSize;
    uint32_t SimIccIdOffset;
    uint32_t SimIccIdSize;
    uint32_t ReadyInfo;
    uint32_t ElementCount;
    uint8_t *TelephoneNumbersRefList;
    uint8_t *DataBuffer;
} MBIM_SUBSCRIBER_READY_STATUS_T;

typedef enum
{
    MBIMRegisterActionAutomatic,
    MBIMRegisterActionManual,
} MBIM_REGISTER_ACTION_E;

typedef enum
{
    MBIMRegisterStateUnknown = 0,
    MBIMRegisterStateDeregistered = 1,
    MBIMRegisterStateSearching = 2,
    MBIMRegisterStateHome = 3,
    MBIMRegisterStateRoaming = 4,
    MBIMRegisterStatePartner = 5,
    MBIMRegisterStateDenied = 6,
} MBIM_REGISTER_STATE_E;

typedef enum
{
    MBIMRegisterModeUnknown = 0,
    MBIMRegisterModeAutomatic = 1,
    MBIMRegisterModeManual = 2,
} MBIM_REGISTER_MODE_E;

typedef enum
{
    MBIM_REGISTRATION_NONE,
    MBIM_REGISTRATION_MANUAL_SELECTION_NOT_AVAILABLE,
    MBIM_REGISTRATION_PACKET_SERVICE_AUTOMATIC_ATTACH,
} MBIM_REGISTRATION_FLAGS_E;

typedef struct
{
    uint32_t NwError;
    uint32_t RegisterState; // MBIM_REGISTER_STATE_E
    uint32_t RegisterMode;
    uint32_t AvailableDataClasses;
    uint32_t CurrentCellularClass;
    uint32_t ProviderIdOffset;
    uint32_t ProviderIdSize;
    uint32_t ProviderNameOffset;
    uint32_t ProviderNameSize;
    uint32_t RoamingTextOffset;
    uint32_t RoamingTextSize;
    uint32_t RegistrationFlag;
    uint8_t *DataBuffer;
} MBIM_REGISTRATION_STATE_INFO_T;

typedef struct
{
    uint32_t NwError;
    uint32_t RegisterState; // MBIM_REGISTER_STATE_E
    uint32_t RegisterMode;
    uint32_t AvailableDataClasses;
    uint32_t CurrentCellularClass;
    uint32_t ProviderIdOffset;
    uint32_t ProviderIdSize;
    uint32_t ProviderNameOffset;
    uint32_t ProviderNameSize;
    uint32_t RoamingTextOffset;
    uint32_t RoamingTextSize;
    uint32_t RegistrationFlag;
    uint32_t PreferredDataClass;
    uint8_t *DataBuffer;
} MBIM_REGISTRATION_STATE_INFO_V2_T;

typedef struct
{
    uint32_t MessageType;   // Specifies the MBIM message type.
    uint32_t MessageLength; // Specifies the total length of this MBIM message in bytes.
    /* Specifies the MBIM message id value.  This value is used to match host sent messages with function responses.
    This value must be unique among all outstanding transactions.
    For notifications, the TransactionId must be set to 0 by the function */
    uint32_t TransactionId;
} MBIM_MESSAGE_HEADER;

typedef struct
{
    uint32_t TotalFragments;  // this field indicates how many fragments there are intotal.
    uint32_t CurrentFragment; // This field indicates which fragment this message is.  Values are 0 to TotalFragments?\1
} MBIM_FRAGMENT_HEADER;

typedef struct
{
    MBIM_MESSAGE_HEADER MessageHeader;
    uint32_t MaxControlTransfer;
} MBIM_OPEN_MSG_T;

typedef struct
{
    MBIM_MESSAGE_HEADER MessageHeader;
    uint32_t Status;
} MBIM_OPEN_DONE_T;

typedef struct
{
    MBIM_MESSAGE_HEADER MessageHeader;
} MBIM_CLOSE_MSG_T;

typedef struct
{
    MBIM_MESSAGE_HEADER MessageHeader;
    uint32_t Status;
} MBIM_CLOSE_DONE_T;

typedef struct
{
    uint8_t uuid[16];
} UUID_T;

typedef struct
{
    MBIM_MESSAGE_HEADER MessageHeader;
    MBIM_FRAGMENT_HEADER FragmentHeader;
    UUID_T DeviceServiceId;           // A 16 byte UUID that identifies the device service the following CID value applies.
    uint32_t CID;                     // Specifies the CID that identifies the parameter being queried for
    uint32_t CommandType;             // 0 for a query operation, 1 for a Set operation
    uint32_t InformationBufferLength; // Size of the Total InformationBuffer, may be larger than current message if fragmented.
    uint8_t InformationBuffer[0];     // Data supplied to device specific to the CID
} MBIM_COMMAND_MSG_T;

typedef struct
{
    MBIM_MESSAGE_HEADER MessageHeader;
    MBIM_FRAGMENT_HEADER FragmentHeader;
    UUID_T DeviceServiceId; // A 16 byte UUID that identifies the device service the following CID value applies.
    uint32_t CID;           // Specifies the CID that identifies the parameter being queried for
    uint32_t Status;
    uint32_t InformationBufferLength; // Size of the Total InformationBuffer, may be larger than current message if fragmented.
    uint8_t InformationBuffer[0];     // Data supplied to device specific to the CID
} MBIM_COMMAND_DONE_T;

typedef struct
{
    MBIM_MESSAGE_HEADER MessageHeader;
    uint32_t ErrorStatusCode;
} MBIM_HOST_ERROR_MSG_T;

typedef struct
{
    MBIM_MESSAGE_HEADER MessageHeader;
    uint32_t ErrorStatusCode;
} MBIM_FUNCTION_ERROR_MSG_T;

typedef struct
{
    MBIM_MESSAGE_HEADER MessageHeader;
    MBIM_FRAGMENT_HEADER FragmentHeader;
    UUID_T DeviceServiceId;           // A 16 byte UUID that identifies the device service the following CID value applies.
    uint32_t CID;                     // Specifies the CID that identifies the parameter being queried for
    uint32_t InformationBufferLength; // Size of the Total InformationBuffer, may be larger than current message if fragmented.
    uint8_t InformationBuffer[0];     // Data supplied to device specific to the CID
} MBIM_INDICATE_STATUS_MSG_T;

typedef struct
{
    uint32_t offset;
    uint32_t size;
} OL_PAIR_LIST;

typedef struct
{
    UUID_T DeviceServiceId;
    uint32_t DssPayload;
    uint32_t MaxDssInstances;
    uint32_t CidCount;
    uint32_t CidList[];
} MBIM_DEVICE_SERVICE_ELEMENT_T;

typedef struct
{
    uint32_t DeviceServicesCount;
    uint32_t MaxDssSessions;
    OL_PAIR_LIST DeviceServicesRefList[];
} MBIM_DEVICE_SERVICES_INFO_T;

typedef enum
{
    MBIMActivationCommandDeactivate = 0,
    MBIMActivationCommandActivate = 1,
} MBIM_ACTIVATION_COMMAND_E;

typedef enum
{
    MBIMCompressionNone = 0,
    MBIMCompressionEnable = 1,
} MBIM_COMPRESSION_E;

typedef enum
{
    MBIMAuthProtocolNone = 0,
    MBIMAuthProtocolPap = 1,
    MBIMAuthProtocolChap = 2,
    MBIMAuthProtocolMsChapV2 = 3,
} MBIM_AUTH_PROTOCOL_E;

typedef enum
{
    MBIMContextIPTypeDefault = 0,
    MBIMContextIPTypeIPv4 = 1,
    MBIMContextIPTypeIPv6 = 2,
    MBIMContextIPTypeIPv4v6 = 3,
    MBIMContextIPTypeIPv4AndIPv6 = 4,
} MBIM_CONTEXT_IP_TYPE_E;

typedef enum
{
    MBIMActivationStateUnknown = 0,
    MBIMActivationStateActivated = 1,
    MBIMActivationStateActivating = 2,
    MBIMActivationStateDeactivated = 3,
    MBIMActivationStateDeactivating = 4,
} MBIM_ACTIVATION_STATE_E;

typedef enum
{
    MBIMVoiceCallStateNone = 0,
    MBIMVoiceCallStateInProgress = 1,
    MBIMVoiceCallStateHangUp = 2,
} MBIM_VOICECALL_STATE_E;

typedef struct
{
    uint32_t SessionId;
    uint32_t ActivationCommand; // MBIM_ACTIVATION_COMMAND_E
    uint32_t AccessStringOffset;
    uint32_t AccessStringSize;
    uint32_t UserNameOffset;
    uint32_t UserNameSize;
    uint32_t PasswordOffset;
    uint32_t PasswordSize;
    uint32_t Compression;  // MBIM_COMPRESSION_E
    uint32_t AuthProtocol; // MBIM_AUTH_PROTOCOL_E
    uint32_t IPType;       // MBIM_CONTEXT_IP_TYPE_E
    UUID_T ContextType;
    uint8_t DataBuffer[0]; /* apn, username, password */
} MBIM_SET_CONNECT_T;

typedef struct
{
    uint32_t SessionId;
    uint32_t ActivationState; // MBIM_ACTIVATION_STATE_E
    uint32_t VoiceCallState;
    uint32_t IPType; // MBIM_CONTEXT_IP_TYPE_E
    UUID_T ContextType;
    uint32_t NwError;
} MBIM_CONNECT_T;

typedef struct
{
    uint32_t OnLinkPrefixLength;
    uint8_t IPv4Address[4];
} MBIM_IPV4_ELEMENT_T;

typedef struct
{
    uint32_t OnLinkPrefixLength;
    uint8_t IPv6Address[16];
} MBIM_IPV6_ELEMENT_T;

typedef struct
{
    uint32_t SessionId;
    uint32_t IPv4ConfigurationAvailable; // bit0~Address, bit1~gateway, bit2~DNS, bit3~MTU
    uint32_t IPv6ConfigurationAvailable; // bit0~Address, bit1~gateway, bit2~DNS, bit3~MTU
    uint32_t IPv4AddressCount;
    uint32_t IPv4AddressOffset;
    uint32_t IPv6AddressCount;
    uint32_t IPv6AddressOffset;
    uint32_t IPv4GatewayOffset;
    uint32_t IPv6GatewayOffset;
    uint32_t IPv4DnsServerCount;
    uint32_t IPv4DnsServerOffset;
    uint32_t IPv6DnsServerCount;
    uint32_t IPv6DnsServerOffset;
    uint32_t IPv4Mtu;
    uint32_t IPv6Mtu;
    uint8_t DataBuffer[];
} MBIM_IP_CONFIGURATION_INFO_T;

typedef struct
{
    uint32_t RSRP;
    uint32_t SNR;
    uint32_t RSRPThreshold;
    uint32_t SNRThreshold;
    uint32_t SystemType;
} MBIM_RSRP_SNR_INFO_T;

typedef struct
{
    uint32_t ElementCount;
    MBIM_RSRP_SNR_INFO_T RsrpSnr[0];
} MBIM_RSRP_SNR_T;

typedef struct
{
    uint32_t Rssi;
    uint32_t ErrorRate;
    uint32_t SignalStrengthInterval;
    uint32_t RssiThreshold;
    uint32_t ErrorRateThreshold;
} MBIM_SIGNAL_STATE_INFO_T;

typedef struct
{
    uint32_t Rssi;
    uint32_t ErrorRate;
    uint32_t SignalStrengthInterval;
    uint32_t RssiThreshold;
    uint32_t ErrorRateThreshold;
    uint32_t RsrpSnrOffset;
    uint32_t RsrpSnrSize;
    uint8_t DataBuffer[];
} MBIM_SIGNAL_STATE_INFO_V2_T;

typedef struct
{
    uint32_t SignalStrengthInterval;
    uint32_t RssiThreshold;
    uint32_t ErrorRateThreshold;
} MBIM_SET_SIGNAL_STATE_T;

typedef struct
{
    UUID_T DeviceServiceId;
    uint32_t CidCount;
    uint32_t DataBuffer[];
} MBIM_EVENT_ENTRY_T;

typedef struct
{
    uint32_t ElementCount;
    OL_PAIR_LIST DeviceServiceSubscribeRefList[];
} MBIM_DEVICE_SERVICE_SUBSCRIBE_LIST_T;

typedef enum
{
    MBIMMsSARControlModeDevice = 0,
    MBIMMsSARControlModeOS = 1,
} MBIM_MS_SAR_CONTROL_MODE_E;

typedef enum
{
    MBIMMsSARBackOffStatusDisabled = 0,
    MBIMMsSARBackOffStatusEnabled = 1,
} MBIM_MS_SAR_BACKOFF_STATE_E;

typedef struct
{
    uint32_t SARAntennaIndex;
    uint32_t SARBAckOffIndex;
} MBIM_MS_SAR_CONFIG_STATE_T;

typedef struct
{
    uint32_t SARMode;          // MBIM_MS_SAR_CONTROL_MODE_E
    uint32_t SARBackOffStatus; // MBIM_MS_SAR_BACKOFF_STATE_E
    uint32_t ElementCount;
    OL_PAIR_LIST SARConfigStatusRefList[0]; // MBIM_MS_SAR_CONFIG_STATE_T
} MBIM_MS_SET_SAR_CONFIG_T;

typedef enum
{
    MBIMMsSARWifiHardwareIntegrated = 0,
    MBIMMsSARWifiHardwareNotIntegrated = 1,
} MBIM_MS_SAR_HARDWARE_WIFI_INTEGRATION_E;

typedef struct
{
    uint32_t SARMode;            // MBIM_MS_SAR_CONTROL_MODE_E
    uint32_t SARBackOffStatus;   // MBIM_MS_SAR_BACKOFF_STATE_E
    uint32_t SARWifiIntegration; // MBIM_MS_SAR_WIFI_HARDWARE_INTEGRATION_E
    uint32_t ElementCount;
    OL_PAIR_LIST SARConfigStatusRefList[0]; // MBIM_MS_SAR_CONFIG_STATE_T
} MBIM_MS_SAR_CONFIG_T;

typedef struct
{
    uint32_t DevicePathOffset;
    uint32_t DevicePathSize;
    uint32_t Timeout;
    uint8_t DataBuffer[];
} MBIM_LIBQMI_PROXY_CONFIG_T;

// DATA
typedef struct
{
    uint32_t SARAntennaIndex;
    uint32_t SARBackOffIndex;
} MBIM_SAR_STATE_BACKOFF_DATA;

// REQ
typedef struct
{
    uint32_t SARMode;
    uint32_t SARBackOffState;
    uint32_t ElementCount;
    uint8_t DataBuffer[0];
} MBIM_SAR_STATE_BACKOFF_REQ;

// RESP
typedef struct
{
    uint32_t SARMode;
    uint32_t SARBackOffStatus;
    uint32_t SARWifiIntegration;
    uint32_t ElementCount;
    OL_PAIR_LIST SARBackOffDataList[];
} MBIM_SAR_STATE_BACKOFF_RESP;

#define QUEC_MBIM_MS_SAR_BACKOFF_SET 0x92F456E8   // QuecMode SET
#define QUEC_MBIM_MS_SAR_BACKOFF_QUERY 0x8204F6F9 // QuecMode QUERY

typedef enum
{
    QUEC_SVC_MSSAR_NULL_STATE = 0,
    QUEC_SVC_MSSAR_BODY_SAR_MODE_STATE_SET,
    QUEC_SVC_MSSAR_BODY_SAR_MODE_STATE_GET,     
    QUEC_SVC_MSSAR_BODY_SAR_PROFILE_VALUE_SET,  
    QUEC_SVC_MSSAR_BODY_SAR_PROFILE_VALUE_GET,
    QUEC_SVC_MSSAR_BODY_SAR_CONFIG_NV_SET,
    QUEC_SVC_MSSAR_BODY_SAR_CONFIG_NV_GET,
    QUEC_SVC_MSSAR_BODY_SAR_ON_TABLE_VALUE_SET,
    QUEC_SVC_MSSAR_BODY_SAR_ON_TABLE_VALUE_GET,
    QUEC_SVC_MSSAR_BODY_SAR_CLEAR_STATE_SET,
} MBIM_SAR_COMMAND;

typedef struct
{
    uint32_t QuecMode;
    uint32_t QuecGetSetState;
    uint32_t QuecSetCount;
    uint8_t DataBuffer[0];
} MBIM_SAR_QUEC_REQ;

typedef struct
{
    uint8_t BodySarMode;    
    uint8_t BodySarProfile; 
    uint8_t BodySarTech1;     
    uint16_t BodySarPower[8]; 
    uint8_t BodySarBand;      
    uint8_t BodySarOnTable;   
} MBIM_SAR_QUEC_CONFIG_DATA;

#define RFNV_DATA_SIZE_MAX 1024
typedef struct ST_DIAG_OVER_MBIM_WRITE_DATA_REQ
{
    unsigned short subsysid;
    unsigned short rf_nv;
    unsigned short write_cmd;
    unsigned short nv_index;
    unsigned short pkt_size;
    unsigned short nv_flag;
    unsigned short item_size;
    unsigned char item_index;
    unsigned char item_data[];
} __attribute__((packed)) DIAG_OVER_MBIM_WRITE_DATA_REQ;

typedef struct ST_DIAG_OVER_MBIM_WRITE_DATA_RSP
{
    unsigned short subsysid;
    unsigned short rf_nv;
    unsigned short write_cmd;
    unsigned short nv_index;
    unsigned short pkt_size;
    unsigned short error_return;
    unsigned short nv_flag;
    unsigned short crc;
    unsigned char endchar;
} __attribute__((packed)) DIAG_OVER_MBIM_WRITE_DATA_RSP;

typedef struct ST_DIAG_OVER_MBIM_READ_DATA_REQ
{
    unsigned short subsysid;
    unsigned short rf_nv;
    unsigned short read_cmd;
    unsigned short nv_index;
    unsigned short pkt_size;
    unsigned short nv_flag;
    unsigned short nv_offset;
    unsigned short crc;
    unsigned char endchar;
} __attribute__((packed)) DIAG_OVER_MBIM_READ_DATA_REQ;

typedef struct ST_DIAG_OVER_MBIM_READ_DATA_RSP
{
    unsigned short subsysid;
    unsigned short rf_nv;
    unsigned short read_cmd;
    unsigned short nv_index;
    unsigned short pkt_size;
    unsigned short error_return;
    unsigned short nv_flag;
    unsigned short byte_read_len;
    unsigned int byte_remaining_len;
    unsigned char item_data;
    unsigned short crc;
    unsigned char endchar;
} DIAG_OVER_MBIM_READ_DATA_RSP;

typedef struct ST_DIAG_OVER_MBIM_TABLE_VERSION_REQ
{
    unsigned short version; // table index of NV29619
    unsigned short crc;     // no use when md5 used
} DIAG_OVER_MBIM_TABLE_VERSION_REQ;

typedef struct ST_DIAG_OVER_MBIM_TABLE_VERSION_RSP
{
    unsigned char header;
    unsigned char version; // table index of NV29619
    unsigned short temp;
    unsigned char md5sum[16]; // md5sum of NV29619
} DIAG_OVER_MBIM_TABLE_VERSION_RSP;

typedef struct ST_MBIM_DEVICE_REBOOT
{
    unsigned short reboot_mode;
} MBIM_DEVICE_REBOOT;

#pragma pack()

int mbim_uuid_cmp(const uint8_t *uuid_byte, const char *uuid_str);
extern int mbim_proxy_configure(const char *dev);
extern int mbim_radio_state_query(MBIM_RADIO_STATE_INFO_T *pRadioState, int is_fcc);
extern int mbim_radio_state_set(MBIM_RADIO_SWITCH_STATE_E RadioState, int is_fcc);
extern int mbim_device_caps_query(char *pHardwareInfo, size_t output_len);
extern int mbim_device_service_subscribe_list_set(const char *uuid, uint32_t CID[], uint32_t CidCount);
extern int mbim_OPEN(void);
extern int mbim_CLOSE(void);
