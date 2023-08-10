/**
 * @file eth_access_task.h
 * @author lubow (lubowu@inalfa-acms.com)
 * @brief
 * @version V0.1.0
 * @date 2023-07-26 18:07:77
 *
 * @copyright Copyright (c) 2023 by lubow, All Rights Reserved.
 *
 */

#ifndef _PLATFORM_SRC_PROCESS_ETH_PROCESS_ETH_ACCESS_TASK_H_
#define _PLATFORM_SRC_PROCESS_ETH_PROCESS_ETH_ACCESS_TASK_H_

#include "eth_access_socket.h"

#include <atomic>
#include <mutex>
#include <string>

class EthAccessTask
{
    enum AccessMgrState : uint8_t
    {
        kAccessMgrInit = 0,
        kAccessMgrFactoryMode,
        kAccessMgrUdpConneciton,
        kAccessMgrUdpSend,
        kAccessMgrUdpRecv,
        kAccessMgrTlsConneciton,
        kAccessMgrTlsSend,
        kAccessMgrTlsEnd,
        kAccessMgrMax
    };

    enum AccessTlsType : uint8_t
    {
        kAccessTlsTypeInvalid   = 0x0,
        kAccessTlsTypeRequest   = 0x1,
        kAccessTlsTypeResponse  = 0x2,
        kAccessTlsTypeKeepAlive = 0x3,
        kAccessTlsTypeError     = 0x80,
        kAccessTlsTypeMax
    };

    enum AccessTlsResponse : uint8_t
    {
        kAccessTlsResponseInvalid = 0,
        kAccessTlsResponseNoAuth,
        kAccessTlsResponseAuth,
        kAccessTlsResponseError,
        kAccessTlsResponseMax
    };

    enum AuthenticationState : uint8_t
    {
        kAuthInvalid = 0,
        kAuthNoAuth,
        kAuthSuccess,
        kAuthFailed,
        kAuthMax
    };

public:
    static EthAccessTask* Instance()
    {
        static EthAccessTask instance;

        return &instance;
    }

    void Start();
    void Stop();

    void Run();

private:
    int16_t GetAccessHeader(AccessTlsType type, uint16_t len, uint8_t* data);
    int16_t GetAccessBody(AccessTlsType type, const uint8_t* body,
                          uint16_t body_len, uint8_t* data);

    AccessTlsResponse AnalysisGatewayData(AccessTlsType  type,
                                          const uint8_t* data, uint16_t len);

    int32_t UdpConnectionHandle();
    int32_t UdpSendData();
    int32_t UdpRecvDataHandle();
    int32_t TlsConnectionHandle();
    int32_t TlsSendData();
    int32_t TlsRecvEndHandle();

    int32_t HandleErrorCode(int32_t error_code);

    std::string GetStrTlsType(AccessTlsType type);
    std::string GetStrTlsStatus(AccessMgrState type);

    uint64_t GetSteadyClockMs();
    uint8_t  GetFactoryMode();

    bool SetMgrStatus(AccessMgrState state);
    bool SetAuthStatus(AuthenticationState state);

    EthAccessTask();
    EthAccessTask(const EthAccessTask&) = delete;

    EthAccessTask& operator=(const EthAccessTask&) = delete;
    virtual ~EthAccessTask();

    std::atomic<AccessMgrState> status_;
    std::mutex                  mutex_;
    EthAccessSocket             socket_;
    uint8_t                     factory_mode_;
    uint8_t                     access_times_;
    std::atomic_bool            start_flag_;
    AuthenticationState         auth_status_;
};

#endif  // _PLATFORM_SRC_PROCESS_ETH_PROCESS_ETH_ACCESS_TASK_H_