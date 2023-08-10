/**
 * @file eth_access_error_code.h
 * @author lubow (lubowu@inalfa-acms.com)
 * @brief
 * @version V0.1.0
 * @date 2023-08-02 13:08:54
 *
 * @copyright Copyright (c) 2023 by lubow, All Rights Reserved.
 *
 */

#ifndef _PLATFORM_SRC_PROCESS_ETH_PROCESS_ETH_ACCESS_ERROR_CODE_H_
#define _PLATFORM_SRC_PROCESS_ETH_PROCESS_ETH_ACCESS_ERROR_CODE_H_

#include <cstdint>
// #include <map>
#include <string>

class EthAccessErrorCode
{
public:
    enum DeviceError : uint8_t
    {
        kTboxDeviceError    = 0,
        kGatewayDeviceError = 1
    };

    enum ErrorCode : uint8_t
    {
        kCloseNotify            = 0,
        kUnexpectedMessage      = 0x0A,
        kBadRecordMac           = 0x14,
        kRecordOverflow         = 0x16,
        kDecompressionFailure   = 0x1E,
        kHandshakeFailure       = 0x28,
        kBadCertificatte        = 0x2A,
        kUnsupportedCertificate = 0x2B,
        kCertificateRevoked     = 0x2C,
        kCertificateExpired     = 0x2D,
        kCertificateUnknown     = 0x2E,
        kIllegalParameter       = 0x2F,
        kUnknownCa              = 0x30,
        kAccessDenied           = 0x31,
        kDecodeError            = 0x32,
        kDecryptError           = 0x33,
        kProtocolVersion        = 0x46,
        kInsufficientSecurity   = 0x47,
        kInternalError          = 0x50,
        kUserCanceled           = 0x5A,
        kNoRenegotiation        = 0x64,
        kUnsupportedExtension   = 0x6E,
        kWorkingModeUnmatched   = 0xFF
    };

    EthAccessErrorCode(DeviceError device, ErrorCode error_code);
    virtual ~EthAccessErrorCode();
    int32_t SendRteErrorCode();

private:
    DeviceError device_error_;
    ErrorCode error_code_;
};

#endif  // _PLATFORM_SRC_PROCESS_ETH_PROCESS_ETH_ACCESS_ERROR_CODE_H_
