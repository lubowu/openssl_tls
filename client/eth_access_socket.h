/**
 * @file eth_access_socket.h
 * @author lubow (lubowu@inalfa-acms.com)
 * @brief
 * @version V0.1.0
 * @date 2023-07-18 16:07:59
 *
 * @copyright Copyright (c) 2023 by lubow, All Rights Reserved.
 *
 */
#ifndef _PLATFORM_SRC_PROCESS_ETH_PROCESS_ETH_ACCESS_SOCKET_H_
#define _PLATFORM_SRC_PROCESS_ETH_PROCESS_ETH_ACCESS_SOCKET_H_

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>

#ifndef WIN32
#include <sys/socket.h>
#endif

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

class EthAccessSocket
{
public:
    enum Status : uint8_t
    {
        DISCONNECT = 1,
        CONNECTED  = 2,
    };
    explicit EthAccessSocket();
    virtual ~EthAccessSocket();

    int32_t OpenUdp();
    int32_t OpenSsl();

    void CloseUdp();
    void CloseSsl();

    int32_t SendUdpMessage(const uint8_t* data, int32_t len);
    int32_t SendSslMessage(const uint8_t* data, int32_t len);
    int32_t RecvUdpMessage(uint8_t* data, int32_t len);
    int32_t RecvSslMessage(uint8_t* data, int32_t len);
    int32_t RecvSslMessage(uint8_t* data, int32_t len, int timeout);
    int32_t RecvSslMessage();

    const Status status() const { return status_.load(); }

private:
    // void    apps_ssl_info_callback(const SSL* s, int where, int ret);
    int32_t CreateUdpSocket();
    int32_t CreateTcpSocket();
    int32_t GetSocketAddr(const std::string& addr, int32_t port,
                          struct sockaddr_in& socket_addr);
    int32_t TcpConnect();
    int32_t SslConnect();

    bool    SetBlockOpt(int32_t socket_fd, bool blocked);
    int32_t SelectTimeOut(int32_t socket_fd, fd_set* read_fds,
                          fd_set* write_fds, int32_t timeout_sec);

    int32_t InitSslCtx();

    void PrintPeerCertificate(SSL* ssl);

    int32_t GetClientCert(const char* path, uint8_t* buf, int32_t buf_len);
    int32_t GetCertChain(const char* path, uint8_t* buf, int32_t buf_len);
    int32_t GetPrivateKey(const char* path, uint8_t* buf, int32_t buf_len);

    static int VerifyCb(int res, X509_STORE_CTX* xs);
    bool LoadCertChainFromSharedMem(SSL_CTX* context, const char* cert_buffer);
    bool LoadUseCertFromSharedMem(SSL_CTX* ctx, const uint8_t* cert);
    bool LoadPrivateKeyFromSharedMem(SSL_CTX* ctx, const uint8_t* key);
    bool LoadRootCertFromSharedMem(SSL_CTX* context,const uint8_t* cert_buffer);

    int32_t tcp_socket_fd_{-1};
    int32_t udp_socket_fd_{-1};
    int32_t failed_times_{0};

    std::mutex          mutex_;
    std::atomic<Status> status_;

    SSL_CTX* ssl_ctx_;
    SSL*     ssl_;
    // EVP_PKEY* evp_key_;
};

#endif  // _PLATFORM_SRC_PROCESS_ETH_PROCESS_ETH_ACCESS_SOCKET_H_