/**
 * @file eth_access_task.cpp
 * @author lubow (lubowu@inalfa-acms.com)
 * @brief
 * @version V0.1.0
 * @date 2023-07-26 19:07:79
 *
 * @copyright Copyright (c) 2023 by lubow, All Rights Reserved.
 *
 */

#include "eth_access_task.h"
#include "eth_access_error_code.h"
// #include "logging.h"
// #include "mid_shareobj_sharedinfo_api.h"
// #include "rte_msg_api.h"

#include <chrono>
#include <map>
#include <string>
#include <iostream>
#include <thread>
#include <iomanip>

void EthAccessTask::Start()
{
    std::cout << "[access] start service.\n";
    if (status_.load() != AccessMgrState::kAccessMgrInit)
    {
        TlsRecvEndHandle();
    }

    start_flag_ = true;
    status_     = AccessMgrState::kAccessMgrFactoryMode;
}
void EthAccessTask::Stop()
{
    std::cout << "[access] stop service.\n";
    start_flag_ = false;
    status_     = AccessMgrState::kAccessMgrTlsEnd;
}


void EthAccessTask::Run()
{
    std::cout << "[access] eth access task start run.\n";

    uint64_t waste_time         = 0;
    uint64_t start_time         = 0;
    uint64_t end_time           = 0;
    bool     access_failed_flag = false;
    int32_t  result             = -1;
    while (true)
    {
        std::cout << "[access] AccessMgrState : " << GetStrTlsStatus(status_) << std::endl;
        waste_time = 0;
        switch (status_.load())
        {
        case kAccessMgrInit:
            SetAuthStatus(AuthenticationState::kAuthInvalid);
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            break;
        case kAccessMgrFactoryMode:
            if (GetFactoryMode() == 0x01)
            {
                SetMgrStatus(AccessMgrState::kAccessMgrTlsConneciton);
                access_failed_flag = false;
                std::cout << "[access] kAccessMgrFactoryMode is normal mode.\n";
            }
            else
            {
                SetAuthStatus(AuthenticationState::kAuthNoAuth);
                SetMgrStatus(AccessMgrState::kAccessMgrInit);
            }
            break;
        case kAccessMgrUdpConneciton:
            if (UdpConnectionHandle() < 0)
            {
                std::cout << "[access] kAccessMgrUdpConneciton error.\n";
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));

                break;
            }
            SetMgrStatus(AccessMgrState::kAccessMgrUdpSend);
            break;
        case kAccessMgrUdpSend:
            result = UdpSendData();
            if (result < 0)
            {
                std::cout << "[access] kAccessMgrUdpSend error.\n";
                SetMgrStatus(AccessMgrState::kAccessMgrUdpConneciton);
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                break;
            }

            SetMgrStatus(AccessMgrState::kAccessMgrUdpRecv);

            access_times_ = 0;
            break;
        case kAccessMgrUdpRecv:
            result = UdpRecvDataHandle();
            if (result < 0)
            {
                std::cout << "[access] kAccessMgrUdpRecv error.\n";
                SetMgrStatus(AccessMgrState::kAccessMgrUdpConneciton);
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                break;
            }
            else if (result == 0)
            {
                std::cout << "[access] kAccessMgrUdpRecv timeout......\n";
                SetMgrStatus(AccessMgrState::kAccessMgrUdpConneciton);
                socket_.CloseUdp();
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }
            else
            {
                if (result == AccessTlsResponse::kAccessTlsResponseAuth)
                {
                    if ((++access_times_) >= 3)
                    {
                        std::cout << "[access] Need Tls auth.\n";
                        access_times_ = 0;
                        SetMgrStatus(AccessMgrState::kAccessMgrTlsConneciton);
                        socket_.CloseUdp();
                    }
                    std::cout
                        << "[access] kAccessMgrUdpRecv auth access times : "
                        << access_times_ << std::endl;
                    std::cout << "[access] kAccessMgrUdpRecv authentication.\n";
                }
                else if (result == AccessTlsResponse::kAccessTlsResponseNoAuth)
                {
                    std::cout
                        << "[access] kAccessMgrUdpRecv no authentication.\n";
                    SetAuthStatus(AuthenticationState::kAuthFailed);
                    SetMgrStatus(AccessMgrState::kAccessMgrTlsEnd);
                    /*The working mode does not match*/
                    EthAccessErrorCode error_code(EthAccessErrorCode::DeviceError::kGatewayDeviceError, EthAccessErrorCode::ErrorCode::kWorkingModeUnmatched);
                    error_code.SendRteErrorCode();
                }
                else
                {
                    std::cout << "[access] kAccessMgrUdpRecv "
                                 "kAccessTlsResponseInvalid.\n";
                    SetMgrStatus(AccessMgrState::kAccessMgrTlsEnd);
                }
            }

            break;
        case kAccessMgrTlsConneciton:
            if (TlsConnectionHandle() < 0)
            {
                if (((++access_times_) >= 3) && access_failed_flag == false)
                {
                    std::cout
                        << "[access] kAccessMgrTlsConneciton access_times_ : "
                        << access_times_ << std::endl;
                    SetAuthStatus(AuthenticationState::kAuthFailed);
                    HandleErrorCode(0);
                    access_times_      = 0;
                    access_failed_flag = true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(3000));
                break;
            }

            SetAuthStatus(AuthenticationState::kAuthSuccess);
            SetMgrStatus(AccessMgrState::kAccessMgrTlsSend);
            break;
        case kAccessMgrTlsSend:
            start_time = GetSteadyClockMs();
            if (TlsSendData() < 0)
            {
                std::cout << "[access] TlsSendData error.\n";
                SetAuthStatus(AuthenticationState::kAuthFailed);

                SetMgrStatus(AccessMgrState::kAccessMgrTlsConneciton);

                break;
            }
            end_time   = GetSteadyClockMs();
            waste_time = (end_time - start_time);
            waste_time = waste_time > 1000 ? 0 : waste_time;
            std::this_thread::sleep_for(
                std::chrono::milliseconds(1000 - waste_time));
            break;
        case kAccessMgrTlsEnd:
            TlsRecvEndHandle();
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        default:
            break;
        }
    }
    std::cout << "[access] eth access task stop run.\n";
}

int16_t EthAccessTask::GetAccessHeader(AccessTlsType type, uint16_t len,
                                       uint8_t* data)
{
    if (data == nullptr)
    {
        std::cout << "[access] GetAccessHeader data is nullptr.\n";
        return -1;
    }
    std::cout << "[access] GetAccessHeader : " << GetStrTlsType(type);
    int16_t data_len = 0;
    data[data_len++] = type;
    data[data_len++] = 0x02;
    data[data_len++] = len >> 8;
    data[data_len++] = len & 0xFF;
    data[data_len++] = 0x00;
    data[data_len++] = 0x01;
    return data_len;
}
int16_t EthAccessTask::GetAccessBody(AccessTlsType type, const uint8_t* body,
                                     uint16_t body_len, uint8_t* data)
{
    std::cout << "[access] GetAccessBody : " << GetStrTlsType(type);
    if (body == nullptr && body_len != 0)
    {
        std::cout << "[access] GetAccessBody body is nullptr.\n";
        return -1;
    }
    int16_t data_len = 0;
    switch (type)
    {
    case kAccessTlsTypeRequest:
        data[0]  = 0x01;
        data_len = 1;
        break;
    case kAccessTlsTypeKeepAlive:
        data[0] = 0x01;
        memmove(&data[1], body, body_len);
        data_len = 7;
        break;
    case kAccessTlsTypeError:
        data[0] = 0x00;
        data[1] = 0x01;
        memmove(&data[2], body, body_len);
        data_len = 8;
        break;
    default:
        break;
    }

    return data_len;
}

EthAccessTask::AccessTlsResponse EthAccessTask::AnalysisGatewayData(
    AccessTlsType type, const uint8_t* data, uint16_t len)
{
    uint16_t data_len = data[2];
    data_len          = (data_len << 8) + data[3];
    std::cout << "[access] AnalysisGatewayData data len : "
              << (int32_t)data_len;
    uint16_t          header_len = 6;
    AccessTlsResponse response   = AccessTlsResponse::kAccessTlsResponseInvalid;
    switch (type)
    {
    case kAccessTlsTypeResponse:
        std::cout << "[access] AnalysisGatewayData data[0] : "
                  << (int32_t)data[header_len];
        if (data[header_len] == 0x01)
        {
            std::cout << "[access] AnalysisGatewayData no auth.\n";
            response = AccessTlsResponse::kAccessTlsResponseNoAuth;
        }
        else if (data[header_len] == 0x10)
        {
            std::cout << "[access] AnalysisGatewayData auth.\n";
            response = AccessTlsResponse::kAccessTlsResponseAuth;
        }
        else
        {
            std::cout << "[access] AnalysisGatewayData other result.\n";
        }
        break;
    case kAccessTlsTypeError:
        std::cout << "[access] AnalysisGatewayData error num.\n";
        response = AccessTlsResponse::kAccessTlsResponseError;
        break;
    default:
        std::cout << "[access] AnalysisGatewayData type error.\n";
        break;
    }

    return response;
}

int32_t EthAccessTask::UdpConnectionHandle()
{
    access_times_ = 0;
    auto result   = socket_.OpenUdp();
    return result;
}
int32_t EthAccessTask::UdpSendData()
{
    uint8_t header_data[64] = {0x0};
    uint8_t body_data[8]    = {0x0};
    uint8_t send_data[128]  = {0x0};

    auto body_len = GetAccessBody(AccessTlsType::kAccessTlsTypeRequest, nullptr,
                                  0, body_data);

    auto header_len = GetAccessHeader(AccessTlsType::kAccessTlsTypeRequest,
                                      body_len, header_data);
    memmove(send_data, header_data, header_len);
    memcpy(send_data + header_len, body_data, body_len);
    return socket_.SendUdpMessage(send_data, header_len + body_len);
}
int32_t EthAccessTask::UdpRecvDataHandle()
{
    uint8_t recv_data[256] = {0x0};
    auto    result = socket_.RecvUdpMessage(recv_data, sizeof(recv_data));
    if (result < 0)
    {
        std::cout << "[access] recv udp message failed.\n";
        return -1;
    }
    else if (result == 0)
    {
        std::cout << "[access] recv udp message time out.\n";
        return 0;
    }
    else
    {
        auto response = AnalysisGatewayData(
            AccessTlsType::kAccessTlsTypeResponse, recv_data, result);
        if (response == kAccessTlsResponseAuth)
        {
            std::cout << "[access] recv gateway authentication.\n";
        }
        else if (response == kAccessTlsResponseNoAuth)
        {
            std::cout << "[access] recv gateway no authentication.\n";
        }
        else
        {
            std::cout << "[access] recv gateway kAccessTlsResponseInvalid.\n";
        }
        return response;
    }

    return 0;
}
int32_t EthAccessTask::TlsConnectionHandle() { return socket_.OpenSsl(); }
int32_t EthAccessTask::TlsSendData()
{
    uint8_t header_data[64] = {0x0};
    uint8_t body_data[8]    = {0x0};
    uint8_t send_data[128]  = {0x0};

    uint8_t dev_id[6] = "TBOX";

    auto body_len = GetAccessBody(AccessTlsType::kAccessTlsTypeKeepAlive,
                                  dev_id, 6, body_data);

    auto header_len = GetAccessHeader(AccessTlsType::kAccessTlsTypeKeepAlive,
                                      body_len, header_data);
    memmove(send_data, header_data, header_len);
    memcpy(send_data + header_len, body_data, body_len);
    std::cout << "send data len : " << header_len + body_len << std::endl;
    for (size_t i = 0; i < header_len + body_len; i++)
        std::cout << std::hex << std::setiosflags(std::ios::uppercase) << std::setfill('0') << std::setw(2) << (int32_t)send_data[i] << " " << std::dec;
    std::cout << std::endl;
    return socket_.SendSslMessage(send_data, header_len + body_len);
}
int32_t EthAccessTask::TlsRecvEndHandle()
{
    socket_.CloseUdp();
    socket_.CloseSsl();
    return 0;
}

std::string EthAccessTask::GetStrTlsType(AccessTlsType type)
{
    std::map<AccessTlsType, std::string> type_str = {
        {kAccessTlsTypeInvalid, "AccessTlsTypeInvalid"},
        {kAccessTlsTypeRequest, "kAccessTlsTypeRequest"},
        {kAccessTlsTypeResponse, "kAccessTlsTypeResponse"},
        {kAccessTlsTypeKeepAlive, "kAccessTlsTypeKeepAlive"},
        {kAccessTlsTypeError, "kAccessTlsTypeError"},
        {kAccessTlsTypeMax, "kAccessTlsTypeMax"}};

    if (type_str.find(type) != type_str.end())
    {
        return type_str[type];
    }

    return "unknown Access type.\n";
}

std::string EthAccessTask::GetStrTlsStatus(AccessMgrState type)
{
    std::map<AccessMgrState, std::string> type_str = {
        {kAccessMgrInit, "kAccessMgrInit"},
        {kAccessMgrFactoryMode, "kAccessMgrFactoryMode"},
        {kAccessMgrUdpConneciton, "kAccessMgrUdpConneciton"},
        {kAccessMgrUdpSend, "kAccessMgrUdpSend"},
        {kAccessMgrUdpRecv, "kAccessMgrUdpRecv"},
        {kAccessMgrTlsConneciton, "kAccessMgrTlsConneciton"},
        {kAccessMgrTlsSend, "kAccessMgrTlsSend"},
        {kAccessMgrTlsEnd, "kAccessMgrTlsEnd"},
        {kAccessMgrMax, "kAccessMgrMax"}};

    if (type_str.find(type) != type_str.end())
    {
        return type_str[type];
    }

    return "unknown Access type.\n";
}

uint64_t EthAccessTask::GetSteadyClockMs()
{
    auto now = std::chrono::steady_clock::now();

    return std::chrono::duration_cast<std::chrono::milliseconds>(
               now.time_since_epoch())
        .count();
    ;
}

uint8_t EthAccessTask::GetFactoryMode()
{
    // DOIP_DIAG_MSG diag_msg;
    // ShareOBJ_API_getDoipData(&diag_msg);
    // factory_mode_ = diag_msg.DoipDiagDID.FactoryMode[0];
    // std::cout << "[access] This is factory mode : "
    //           << static_cast<int32_t>(factory_mode_);
    // /************test*************/
    factory_mode_ = 0x01;
    return factory_mode_;
}

bool EthAccessTask::SetMgrStatus(EthAccessTask::AccessMgrState state)
{
    if (start_flag_ == false)
    {
        std::cout << "[access] stop set status.\n";
        return false;
    }

    status_ = state;
    std::cout << "[access] set status : " << GetStrTlsStatus(status_) << std::endl;
    return true;
}

int32_t EthAccessTask::HandleErrorCode(int32_t error_code) {}

bool EthAccessTask::SetAuthStatus(EthAccessTask::AuthenticationState state)
{
    auth_status_ = state;
    std::cout << "[access] Setting auth status : "
              << static_cast<int32_t>(auth_status_);

    /**RTE*/
    // uint8_t data = auth_status_;
    // RTE_API_SendMsg_CommonMsg(RteCommonMsgId::kRteCommonMsgIdAuthStatus, &data,
    //                           sizeof(data));
    return true;
}

EthAccessTask::EthAccessTask() :
    status_(AccessMgrState::kAccessMgrInit),
    socket_(),
    auth_status_(AuthenticationState::kAuthInvalid)
{}

EthAccessTask::~EthAccessTask() {}

void* eth_access_taskMain(void* params) { EthAccessTask::Instance()->Run(); }