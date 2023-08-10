/**
 * @file eth_access_error_code.cpp
 * @author lubow (lubowu@inalfa-acms.com)
 * @brief
 * @version V0.1.0
 * @date 2023-08-02 17:08:36
 *
 * @copyright Copyright (c) 2023 by lubow, All Rights Reserved.
 *
 */

#include "eth_access_error_code.h"

#include <iostream>
// #include "logging.h"
// #include "rte_msg_api.h"

EthAccessErrorCode::EthAccessErrorCode(DeviceError device,
                                       ErrorCode   error_code) :
    device_error_(device), error_code_(error_code)
{}
EthAccessErrorCode::~EthAccessErrorCode() {}

int32_t EthAccessErrorCode::SendRteErrorCode()
{
    uint8_t error_data[64] = {0x0};
    error_data[0]          = device_error_;
    error_data[1]          = error_code_;

    std::cout << "Send error code data[0] : " << (int)error_data[0] << ", data[2] : " << error_data[1] << std::endl;
    // RTE_API_SendMsg_CommonMsg(RteCommonMsgId::kRteCommonMsgIdAuthErrorCode,
    //                           error_data, 2);
    return 0;
}