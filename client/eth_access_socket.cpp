/**
 * @file eth_access_socket.cpp
 * @author lubow (lubowu@inalfa-acms.com)
 * @brief
 * @version V0.1.0
 * @date 2023-07-18 16:07:25
 *
 * @copyright Copyright (c) 2023 by lubow, All Rights Reserved.
 *
 */

#include "eth_access_socket.h"

#include <sys/types.h>
#ifndef WIN32
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>

// #define TCP_SERVER_ADDR "x509.itls.cn-shanghai.aliyuncs.com"
#define TCP_SERVER_ADDR "127.0.0.1"
// #define TCP_SERVER_ADDR "192.168.4.45"
#define UDP_SERVER_ADDR TCP_SERVER_ADDR
#define UDP_TBOX_ADDR   "127.0.0.1"
// #define UDP_TBOX_ADDR     "192.168.4.43"
// #define TCP_SERVER_PORT (1883)
#define TCP_SERVER_PORT (30504)
#define UDP_SERVER_PORT TCP_SERVER_PORT

#define CONNECT_TIMEOUT      (3)
#define SEND_RECEIVE_TIMEOUT (3)
#define UDP_RECV_TIMEOUT     (2)

#define PREFERRED_SSL_CIPHER_LIST "ECDHE-ECDSA-AES128-GCM-SHA256"

// #define ROOT_CERT_PATH
// "/home/lubow/work/src/test/Tls/client/pki/root_cert.crt" #define
// CLIENT_CERT_PATH  "/home/lubow/work/src/test/Tls/client/pki/tbox_cert.crt"
// #define CLIENT_KEY_PATH
// "/home/lubow/work/src/test/Tls/client/pki/private_cert.key"

#define ROOT_CERT_PATH \
    "/home/lubow/work/src/test/Tls/client/pki/ed25519/root_ed25519_cert.pem"
#define CLIENT_CERT_PATH \
    "/home/lubow/work/src/test/Tls/client/pki/ed25519/tbox_ed25519_cert.pem"
#define CLIENT_KEY_PATH                                 \
    "/home/lubow/work/src/test/Tls/client/pki/ed25519/" \
    "private_ed25519_cert.key"

static const uint8_t root_ca_cert[] = "-----BEGIN CERTIFICATE-----\n" \
"MIIBojCCAVSgAwIBAgIILniCUS7Dw9swBQYDK2VwMEgxCzAJBgNVBAYTAkNOMRUw\n"\
"EwYDVQQKDAxURVNUX0JKRVZfQ0ExIjAgBgNVBAMMGVRFU1RfQkpFVl9ST09UX0NB\n"\
"X0VEMjU1MTkwHhcNMjMwMTE3MDczOTQwWhcNNDIwMzE4MDczOTQwWjBHMQswCQYD\n"\
"VQQGEwJDTjEVMBMGA1UECgwMVEVTVF9CSkVWX0NBMSEwHwYDVQQDDBhURVNUX0JK\n"\
"RVZfU1VCX0NBX0VEMjU1MTkwKjAFBgMrZXADIQAg2tAyUZbo0sALWRgkeepZOH1f\n"\
"SvpTVj91G8CHUnJXuqNdMFswHwYDVR0jBBgwFoAUVth2wOZK00GLjxwf2dT/Alfd\n"\
"yjcwHQYDVR0OBBYEFFTIXSz0SFb2bYBzZ4vPDDxIKwcFMAwGA1UdEwQFMAMBAf8w\n"\
"CwYDVR0PBAQDAgEOMAUGAytlcANBADuQ0qFdFlSwRAd6yF6Q0CewDWnLMxgV1BcU\n"\
"NR0C2Y8MZXTtx+YzwLnJel83c+9MmW5GCg/elfEpl03YQszbOQ0=\n"\
"-----END CERTIFICATE-----\n"\
"-----BEGIN CERTIFICATE-----\n"\
"MIIBpTCCAVegAwIBAgIILFHtYS68P78wBQYDK2VwMEgxCzAJBgNVBAYTAkNOMRUw\n"\
"EwYDVQQKDAxURVNUX0JKRVZfQ0ExIjAgBgNVBAMMGVRFU1RfQkpFVl9ST09UX0NB\n"\
"X0VEMjU1MTkwIBcNMjIwNzA1MDYxMzQyWhgPMjA1MjA2MjcwNjEzNDJaMEgxCzAJ\n"\
"BgNVBAYTAkNOMRUwEwYDVQQKDAxURVNUX0JKRVZfQ0ExIjAgBgNVBAMMGVRFU1Rf\n"\
"QkpFVl9ST09UX0NBX0VEMjU1MTkwKjAFBgMrZXADIQDmYIIucIKPuZEqQVqNupra\n"\
"3hct+EkyC6M0JgCzgqW4KqNdMFswCwYDVR0PBAQDAgEGMAwGA1UdEwQFMAMBAf8w\n"\
"HQYDVR0OBBYEFFbYdsDmStNBi48cH9nU/wJX3co3MB8GA1UdIwQYMBaAFFbYdsDm\n"\
"StNBi48cH9nU/wJX3co3MAUGAytlcANBAC8TkaHC0+igIEmfwWD7OUNC+ru/UZ3i\n"\
"jXzr4+NOotdALoDuTy6orEfjYNXJt5ziiGzzrM6oYlJMNnjewot6hAs=\n"\
"-----END CERTIFICATE-----";
static const uint8_t tbox_ca_cert[] = 
"-----BEGIN CERTIFICATE-----\n"\
"MIIBzzCCAYGgAwIBAgIILYnUtpfqqOMwBQYDK2VwMEcxCzAJBgNVBAYTAkNOMRUw\n"\
"EwYDVQQKDAxURVNUX0JKRVZfQ0ExITAfBgNVBAMMGFRFU1RfQkpFVl9TVUJfQ0Ff\n"\
"RUQyNTUxOTAeFw0yMzA4MTAwNTM2NThaFw0zMzA4MDcwNTM2NThaMGQxCzAJBgNV\n"\
"BAYTAkNOMRUwEwYDVQQKDAxCQUlDX0JKRVZTSUcxFjAUBgNVBAoMDUJBSUNfU1NM\n"\
"X1RCT1gxJjAkBgNVBAMMHVRCT1hfWktCSjQxVEVTVDAwMDAwMl9FRDI1NTE5MCow\n"\
"BQYDK2VwAyEAeUdKfxg9HPPWhA0RApWVWHnhPawLYEyYS/oMLhmPlsmjbjBsMB8G\n"\
"A1UdIwQYMBaAFFTIXSz0SFb2bYBzZ4vPDDxIKwcFMB0GA1UdDgQWBBS2bOfcUOmj\n"\
"mos+0js5cIWTeVRFPDALBgNVHQ8EBAMCAf4wHQYDVR0lBBYwFAYIKwYBBQUHAwEG\n"\
"CCsGAQUFBwMCMAUGAytlcANBAJdWRXzA7AgFmHfAh7SOlC2vQo1IQ1fsXNuZN3q8\n"\
"exxl6hNOHeDHf2JfpP16vMrsnz1VGLRgbh1idgSJ4xY3vws=\n"\
"-----END CERTIFICATE-----";
static const uint8_t private_ed25519_key[] =
    "-----BEGIN PRIVATE KEY-----\n" \
    "MC4CAQAwBQYDK2VwBCIEICYkHLQ1qwssc4aOHBLgPY9zGFdITLxFfG0XAYvBoaJv\n" \
    "-----END PRIVATE KEY-----";

// #define USE_CERTIFICATE_FILE

static struct sockaddr_in udp_addr;
static struct sockaddr_in tcp_addr;

void apps_ssl_info_callback(const SSL* s, int where, int ret)
{
    std::cout << "apps_ssl_info_callback *************** : ret : " << ret
              << std::endl;
    const char* str;
    int         w;

    w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
        str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
        str = "SSL_accept";
    else
        str = "undefined";

    if (where & SSL_CB_LOOP)
    {
        std::cout << "where & SSL_CB_LOOP " << str << " : "
                  << SSL_state_string_long(s) << std::endl;
        // BIO_printf(bio_err, "%s:%s\n", str, SSL_state_string_long(s));
    }
    else if (where & SSL_CB_ALERT)
    {
        str = (where & SSL_CB_READ) ? "read" : "write";
        std::cout << "SSL3 alert " << str << " : "
                  << SSL_alert_type_string_long(ret) << " : "
                  << SSL_alert_desc_string_long(ret) << std::endl;
        // BIO_printf(bio_err, "SSL3 alert %s:%s:%s\n",
        //            str,
        //            SSL_alert_type_string_long(ret),
        //            SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_EXIT)
    {
        if (ret == 0)
            std::cout << "where & SSL_CB_EXIT " << str << ":failed in "
                      << SSL_state_string_long(s) << std::endl;
        // BIO_printf(bio_err, "%s:failed in %s\n",
        //            str, SSL_state_string_long(s));
        else if (ret < 0)
            std::cout << "where & SSL_CB_EXIT " << str << ":error in "
                      << SSL_state_string_long(s) << std::endl;
        // BIO_printf(bio_err, "%s:error in %s\n",
        //            str, SSL_state_string_long(s));
    }
}

EthAccessSocket::EthAccessSocket()
{
    status_.store(Status::DISCONNECT);
    std::cout << "[access] get tcp socket address.\n";
    if (GetSocketAddr(TCP_SERVER_ADDR, TCP_SERVER_PORT, tcp_addr))
    {
        std::cout << "[access] get socket addr failed.\n";
    }
    std::cout << "[access] get udp socket address.\n";
    if (GetSocketAddr(UDP_SERVER_ADDR, UDP_SERVER_PORT, udp_addr))
    {
        std::cout << "[access] get socket addr failed.\n";
    }
}
EthAccessSocket::~EthAccessSocket() {}

int32_t EthAccessSocket::OpenUdp()
{
    std::cout << "[access] OpenUdp start.\n";
    auto result = CreateUdpSocket();
    if (result < 0)
    {
        std::cout << "[access] OpenUdp failed.\n";
        return result;
    }
    return result;
}
int32_t EthAccessSocket::OpenSsl()
{
    if (status() == Status::CONNECTED)
    {
        std::cout << "[access] ssl are already connected.\n";
        return 0;
    }
    auto result = InitSslCtx();
    if (result < 0)
    {
        std::cout << "[access] OpenSsl InitSslCtx error.\n";
        return result;
    }

    result = CreateTcpSocket();
    if (result < 0)
    {
        std::cout << "[access] OpenSsl CreateTcpSocket error.\n";
        return result;
    }

    result = TcpConnect();
    if (result < 0)
    {
        std::cout << "[access] OpenSsl TcpConnect error.\n";
        return result;
    }

    result = SslConnect();
    if (result < 0)
    {
        std::cout << "[access] OpenSsl SslConnect error.\n";
        return result;
    }
    status_.store(Status::CONNECTED);
    return result;
}

int32_t EthAccessSocket::CreateUdpSocket()
{
    std::cout << "[access] create udp socket.\n";
    udp_socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket_fd_ < 0)
    {
        std::cout << "[access] create udp socket failed.\n";
        return -1;
    }
    return 0;
}
int32_t EthAccessSocket::CreateTcpSocket()
{
    std::cout << "[access] create tcp socket.\n";
    tcp_socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_socket_fd_ < 0)
    {
        std::cout << "[access] create tcp socket failed\n";
        return -1;
    }
    return 0;
}

int32_t EthAccessSocket::GetSocketAddr(const std::string& addr, int32_t port,
                                       struct sockaddr_in& socket_addr)
{
    memset(&socket_addr, 0, sizeof(socket_addr));
    std::cout << "[access] connect ip: " << addr << ", port: " << port;
    struct hostent* host;
    if ((host = gethostbyname(addr.c_str())) == NULL)
    {
        std::cout << "[access] gethostbyname failed,"
                  << " errno: " << errno << " msg: " << strerror(errno);
        return -1;
    }

    socket_addr.sin_family = AF_INET;
    socket_addr.sin_port   = htons(port);
    socket_addr.sin_addr   = *((struct in_addr*)host->h_addr);
    char* ip               = inet_ntoa(socket_addr.sin_addr);
    std::cout << "[access] connect to server domain: " << addr
              << ", ip: " << std::string(ip) << ", port: " << port;
    return 0;
}
int32_t EthAccessSocket::TcpConnect()
{
    SetBlockOpt(tcp_socket_fd_, false);
    if (connect(tcp_socket_fd_, reinterpret_cast<struct sockaddr*>(&tcp_addr),
                sizeof(tcp_addr)) < 0)
    {
        if (errno != EINPROGRESS)
        {
            std::cout << "[access] socket connect failed,"
                      << " errno: " << errno << " msg: " << strerror(errno);
            return -1;
        }
    }
    else
    {
        std::cout << "[access] socket connect succeeded.\n";
        SetBlockOpt(tcp_socket_fd_, true);
        return 0;
    }
    fd_set write_fds;
    auto   result =
        SelectTimeOut(tcp_socket_fd_, nullptr, &write_fds, CONNECT_TIMEOUT);
    if (result <= 0)
    {
        std::cout << "[access] socket connect failed.\n";
        CloseSsl();
        return -1;
    }

    int       error = -1;
    socklen_t len   = sizeof(socklen_t);
    if (getsockopt(tcp_socket_fd_, SOL_SOCKET, SO_ERROR, &error,
                   (socklen_t*)&len) < 0)
    {
        std::cout << "[access] getsockopt error!!\n";
        SetBlockOpt(tcp_socket_fd_, true);
        return -1;
    }
    else
    {
        if (error == 0)
        {
            std::cout << "[access] socket connect successed\n";
        }
        else
        {
            std::cout << "[access] connect getsockopt error, error value: "
                      << error << " msg: " << strerror(error);
            SetBlockOpt(tcp_socket_fd_, true);
            return -1;
        }
    }
    SetBlockOpt(tcp_socket_fd_, true);

    return 0;
}

int32_t EthAccessSocket::SslConnect()
{
    ssl_ = SSL_new(ssl_ctx_);
    if (!ssl_)
    {
        std::cout << "[access] [SSL] can't get ssl from ctx\n";
        return -1;
    }

    SSL_set_fd(ssl_, tcp_socket_fd_);
    // connect to TSP server using TLS
    int ret = 0;
    ret     = SSL_connect(ssl_);
    if (ret != 1)
    {
        int err = ERR_get_error();
        std::cout << "[access] [SSL] Connect error code: " << err
                  << ", string: " << ERR_error_string(err, NULL) << std::endl;

        return -1;
    }
    std::cout << "SSL connection using : " << SSL_get_cipher(ssl_) << std::endl;

    // output server certificate info
    PrintPeerCertificate(ssl_);

    return 0;
}
int32_t EthAccessSocket::SendUdpMessage(const uint8_t* data, int32_t len)
{
    if (data == nullptr || len == 0)
    {
        std::cout << "[access] SendUdpMessage param error.\n";
        return -1;
    }
    if (udp_socket_fd_ < 0)
    {
        std::cout << "[access] udp socket is close.\n";
        return -1;
    }
    int32_t result = -1;
    fd_set  write_fds;
    result = SelectTimeOut(udp_socket_fd_, nullptr, &write_fds,
                           SEND_RECEIVE_TIMEOUT);
    if (result <= 0)
    {
        std::cout << "[access] udp send msg failed.\n";
        CloseUdp();
        return -1;
    }

    int addr_len = sizeof(struct sockaddr_in);

    result = sendto(udp_socket_fd_, data, len, 0, (struct sockaddr*)&udp_addr,
                    (socklen_t)addr_len);
    if (result < 0)
    {
        std::cout << "[access] udp send msg failed.\n";
    }
    return result;
}
int32_t EthAccessSocket::SendSslMessage(const uint8_t* data, int32_t len)
{
    if (data == nullptr || len == 0)
    {
        std::cout << "[access] SendSslMessage param error.\n";
        return -1;
    }

    if (status() == Status::DISCONNECT)
    {
        std::cout << "[access] SendSslMessage not connected.\n";
        return -1;
    }

    fd_set write_fds;
    auto   result = SelectTimeOut(tcp_socket_fd_, nullptr, &write_fds,
                                  SEND_RECEIVE_TIMEOUT);
    if (result <= 0)
    {
        std::cout << "[access] SendSslMessage select error.\n";
        CloseSsl();
        return -1;
    }

    auto write_len = SSL_write(ssl_, data, len);
    if (write_len <= 0)
    {
        std::cout << "[access] RecvSslMessage SSL_read error : "
                  << SSL_get_error(ssl_, write_len);
        CloseSsl();
        return -1;
    }
    return write_len;
}
int32_t EthAccessSocket::RecvUdpMessage(uint8_t* data, int32_t len)
{
    if (data == nullptr || len == 0)
    {
        std::cout << "[access] RecvUdpMessage param error.\n";
        return -1;
    }
    if (udp_socket_fd_ < 0)
    {
        std::cout << "[access] udp socket is close.\n";
        return -1;
    }

    fd_set read_fds;
    auto   result =
        SelectTimeOut(udp_socket_fd_, &read_fds, nullptr, UDP_RECV_TIMEOUT);
    if (result < 0)
    {
        std::cout << "[access] SelectTimeOut udp recv msg failed.\n";
        CloseUdp();
        return -1;
    }

    if (result == 0)
    {
        std::cout << "[access] udp recv msg timeout ...\n";

        return result;
    }

    socklen_t addr_len = sizeof(udp_addr);
    result = recvfrom(udp_socket_fd_, data, len, 0, (struct sockaddr*)&udp_addr,
                      &addr_len);
    if (result < 0)
    {
        std::cout << "[access] recvfrom udp recv msg failed. : error : "
                  << errno;
    }
    return result;
}

int32_t EthAccessSocket::RecvSslMessage(uint8_t* data, int32_t len, int timeout)
{
    if (data == nullptr || len == 0)
    {
        std::cout << "[access] RecvSslMessage param error.\n";
        return -1;
    }
    fd_set read_fds;
    int    recv_len = -1;
    auto   result = SelectTimeOut(tcp_socket_fd_, &read_fds, nullptr, timeout);
    if (result < 0)
    {
        std::cout << "[access] RecvSslMessagefailed.\n";
        CloseSsl();
        return -1;
    }
    else if (result == 0)
    {
        std::cout << "[access] select timeout, no data to receive.\n";
        return 0;
    }
    else
    {
        recv_len = RecvSslMessage(data, len);
    }
    return recv_len;
}

int32_t EthAccessSocket::RecvSslMessage(uint8_t* data, int32_t len)
{
    if (data == nullptr || len == 0)
    {
        std::cout << "[access] RecvSslMessage param error.\n";
        return -1;
    }

    if (status() == Status::DISCONNECT)
    {
        std::cout << "[access] RecvSslMessage not connected.\n";
        return -1;
    }

    auto recv_len = SSL_read(ssl_, data, len);
    if (recv_len <= 0)
    {
        std::cout << "[access] RecvSslMessage SSL_read error : "
                  << SSL_get_error(ssl_, recv_len);
        CloseSsl();
        return -1;
    }

    return recv_len;
}

bool EthAccessSocket::SetBlockOpt(int32_t socket_fd, bool blocked)
{
    int flags;
    flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags < 0)
    {
        std::cout << "[access] fcntl error !!\n";
        return false;
    }
    if (blocked)
    {
        std::cout << "[access] Set BLOCK !!\n";
        flags &= ~O_NONBLOCK;
    }
    else
    {
        std::cout << "[access] Set NONBLOCK !!\n";
        flags |= O_NONBLOCK;
    }
    if (fcntl(socket_fd, F_SETFL, flags) < 0)
    {
        std::cout << "[access] fcntl error !!\n";
        return false;
    }

    return true;
}

int32_t EthAccessSocket::SelectTimeOut(int32_t socket_fd, fd_set* read_fds,
                                       fd_set* write_fds, int32_t timeout_sec)
{
    struct timeval timeout;
    timeout.tv_sec  = timeout_sec;
    timeout.tv_usec = 0;
    if (read_fds != nullptr)
    {
        FD_ZERO(read_fds);
        FD_SET(socket_fd, read_fds);
        std::cout << "[access] Set timeout read fds.\n";
    }
    if (write_fds != nullptr)
    {
        FD_ZERO(write_fds);
        FD_SET(socket_fd, write_fds);
        std::cout << "[access] Set timeout write fds.\n";
    }

    auto result = select(socket_fd + 1, read_fds, write_fds, nullptr, &timeout);
    switch (result)
    {
    case -1:
        std::cout << "[access] connect error : " << strerror(errno)
                  << ", errno : " << errno;
        break;
    case 0:
        std::cout << "[access] select timeout ...\n";
        break;
    default:
        if (read_fds != nullptr)
        {
            if (FD_ISSET(socket_fd, read_fds))
            {
                std::cout << "[access] select has read data.\n";
            }
        }
        if (write_fds != nullptr)
        {
            if (FD_ISSET(socket_fd, write_fds))
            {
                std::cout << "[access] select has write data.\n";
            }
        }
        break;
    }

    return result;
}

void EthAccessSocket::CloseUdp()
{
    if (udp_socket_fd_ >= 0)
    {
        close(udp_socket_fd_);
    }
    udp_socket_fd_ = -1;
}
void EthAccessSocket::CloseSsl()
{
    std::cout << "[access] Close connected.\n";
    std::lock_guard<std::mutex> lock(mutex_);

    std::cout << "[access] Close ssl connection.\n";
    if (tcp_socket_fd_ != -1)
    {
        shutdown(tcp_socket_fd_, 2);
        std::cout << "[access] shutdown tcp connection.\n";
    }

    if (ssl_)
    {
        SSL_free(ssl_);
        ssl_ == nullptr;
        std::cout << "[access] SSL_free ssl.\n";
    }

    if (ssl_ctx_)
    {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        std::cout << "[access] SSL_CTX_free ssl_ctx.\n";
    }

    if (tcp_socket_fd_ != -1)
    {
        close(tcp_socket_fd_);
        tcp_socket_fd_ = -1;
        std::cout << "[access] Close tcp connection.\n";
    }
    status_.store(Status::DISCONNECT);
}

// void EthAccessSocket::apps_ssl_info_callback(const SSL *s, int where, int
// ret)
// {
//     // const char *str;
//     // int w;

//     // w = where & ~SSL_ST_MASK;

//     // if (w & SSL_ST_CONNECT)
//     //     str = "SSL_connect";
//     // else if (w & SSL_ST_ACCEPT)
//     //     str = "SSL_accept";
//     // else
//     //     str = "undefined";

//     // if (where & SSL_CB_LOOP) {
//     //     BIO_printf(bio_err, "%s:%s\n", str, SSL_state_string_long(s));
//     // } else if (where & SSL_CB_ALERT) {
//     //     str = (where & SSL_CB_READ) ? "read" : "write";
//     //     BIO_printf(bio_err, "SSL3 alert %s:%s:%s\n",
//     //                str,
//     //                SSL_alert_type_string_long(ret),
//     //                SSL_alert_desc_string_long(ret));
//     // } else if (where & SSL_CB_EXIT) {
//     //     if (ret == 0)
//     //         BIO_printf(bio_err, "%s:failed in %s\n",
//     //                    str, SSL_state_string_long(s));
//     //     else if (ret < 0)
//     //         BIO_printf(bio_err, "%s:error in %s\n",
//     //                    str, SSL_state_string_long(s));
//     // }
// }

int32_t EthAccessSocket::InitSslCtx()
{
    // const int8_t default_pw_str[10] = "1111";
    // print_client_cert(CERT_PATH);
    // registers the libssl error strings
    SSL_load_error_strings();

    // registers the available SSL/TLS ciphers and digests
    SSL_library_init();

    // creates a new SSL_CTX object as framework to establish TLS/SSL
    ssl_ctx_ = SSL_CTX_new(TLSv1_2_method());
    if (ssl_ctx_ == NULL)
    {
        return -1;
    }

    // SSL_CTX_set_info_callback(ssl_ctx_,
    // std::bind(&EthAccessSocket::apps_ssl_info_callback,
    // std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    SSL_CTX_set_info_callback(ssl_ctx_, apps_ssl_info_callback);

    // passwd is supplied to protect the private key,when you want to read key
    // SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx_,
    //                                        const_cast<int8_t*>(default_pw_str));

    // set cipher ,when handshake client will send the cipher list to server
    const long flags =
        SSL_OP_NO_COMPRESSION | SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
    SSL_CTX_set_options(ssl_ctx_, flags);
    // SSL_CTX_set_cipher_list(ssl_ctx_,"HIGH:MEDIA:LOW:!DH");
    // SSL_CTX_set_cipher_list(ssl_ctx_, "HIGH:!aNULL:!MD5");
    // SSL_CTX_set_cipher_list(ssl_ctx_,PREFERRED_SSL_CIPHER_LIST);
    // SSL_CTX_set_cipher_list(ssl_ctx_,"AES128-SHA");

    // set verify ,when recive the server certificate and verify it
    // and verify_cb function will deal the result of verification
    SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, VerifyCb);

    // sets the maximum depth for the certificate chain verification that shall
    // be allowed for ctx
    SSL_CTX_set_verify_depth(ssl_ctx_, 10);

#ifdef USE_CERTIFICATE_FILE
    if (access(ROOT_CERT_PATH, F_OK) != 0)
    {
        std::cout << "[access] [SSL] " << ROOT_CERT_PATH << " isn't exist\n";
        return -1;
    }

    if (access(CLIENT_CERT_PATH, F_OK) != 0)
    {
        std::cout << "[access] [SSL] " << CLIENT_CERT_PATH << " isn't exist\n";
        return -1;
    }

    // load the certificate for verify server certificate, CA file usually load
    if (SSL_CTX_load_verify_locations(ssl_ctx_, ROOT_CERT_PATH, NULL) <= 0)
    {
        std::cout << "[access] [SSL] SSL_CTX_load_verify_locations : "
                  << ERR_error_string(ERR_get_error(), NULL) << std::endl;
    }

    // load user certificate,this cert will be send to server for server verify
    if (SSL_CTX_use_certificate_file(ssl_ctx_, CLIENT_CERT_PATH,
                                     SSL_FILETYPE_PEM) <= 0)
    // if (SSL_CTX_use_certificate_chain_file(ssl_ctx_, CLIENT_CERT_PATH) <= 0)
    {
        std::cout << "[access] [SSL] SSL_CTX_use_certificate_file error : "
                  << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        std::cout << "[access] [SSL] SSL_CTX_use_certificate_file SSL error : "
                  << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return -1;
    }

    // load user private key
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, CLIENT_KEY_PATH,
                                    SSL_FILETYPE_PEM) <= 0)
    {
        std::cout << "[access] [SSL] privatekey file error : "
                  << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return -1;
    }
#else
    // uint8_t buf[8192] = {0x0};
    // auto    len       = GetCertChain(ROOT_CERT_PATH, buf, sizeof(buf));
    // LoadRootCertFromSharedMem(ssl_ctx_, (const uint8_t*)buf);
    LoadRootCertFromSharedMem(ssl_ctx_, root_ca_cert);

    // memset(buf, 0, sizeof(buf));
    // GetCertChain(CLIENT_CERT_PATH, buf, sizeof(buf));
    // LoadUseCertFromSharedMem(ssl_ctx_, (const uint8_t*)buf);
    LoadUseCertFromSharedMem(ssl_ctx_, tbox_ca_cert);
    // memset(buf, 0, sizeof(buf));
    // GetPrivateKey(CLIENT_KEY_PATH, buf, sizeof(buf));
    // LoadPrivateKeyFromSharedMem(ssl_ctx_, buf);
    LoadPrivateKeyFromSharedMem(ssl_ctx_, private_ed25519_key);
#endif

    if (!SSL_CTX_check_private_key(ssl_ctx_))
    {
        std::cout << "[access] [SSL] Check private key failed : "
                  << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        return -1;
    }

    return 0;
}

void EthAccessSocket::PrintPeerCertificate(SSL* ssl)
{
    X509*      cert      = NULL;
    X509_NAME* name      = NULL;
    char       buf[8192] = {0};
    BIO*       bio_cert  = NULL;

    // get server certificate
    cert = SSL_get_peer_certificate(ssl);
    // get subject name
    name = X509_get_subject_name(cert);
    X509_NAME_oneline(name, buf, 8191);
    std::cout << "[access] [SSL] ServerSubjectName: " << std::string(buf)
              << std::endl;
    memset(buf, 0, sizeof(buf));
    bio_cert = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio_cert, cert);
    BIO_read(bio_cert, buf, 8191);
    // server certificate info
    std::cout << "[access] [SSL] SERVER CERT: " << std::string(buf)
              << std::endl;
    if (bio_cert)
    {
        BIO_free(bio_cert);
    }
    if (cert)
    {
        X509_free(cert);
    }
}

int32_t EthAccessSocket::GetPrivateKey(const char* path, uint8_t* buf,
                                       int32_t buf_len)
{
    if (!path)
    {
        std::cout << "[access] [SSL] path is nullptr.\n";
        return -1;
    }

    if (!buf)
    {
        std::cout << "[access] [SSL] buf is nullptr.\n";
        return -1;
    }
    if (access(path, F_OK) != 0)
    {
        std::cout << "[access] [SSL] cert files is not exist\n";
        return -1;
    }
    BIO*  bio_cert = NULL;
    FILE* fp       = NULL;
    // const int8_t PEM_read_str[10] = "1111";

    fp = fopen(path, "rb");
    if (fp == NULL)
    {
        std::cout << "[access] [SSL] client certificate open error\n";
        return -1;
    }
    EVP_PKEY* evpkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    if (evpkey == NULL)
    {
        fclose(fp);
        return -1;
    }

    bio_cert = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio_cert, evpkey, nullptr, nullptr, 0, nullptr,
                             nullptr);

    // certificate info
    auto len = BIO_read(bio_cert, buf, buf_len);
    std::cout << "[access] [SSL] private key : \n" << buf << std::endl;

    fclose(fp);
    EVP_PKEY_free(evpkey);
    BIO_free(bio_cert);
}

int32_t EthAccessSocket::GetCertChain(const char* path, uint8_t* buf,
                                      int32_t buf_len)
{
    if (!path)
    {
        std::cout << "[access] [SSL] path is nullptr.\n";
        return -1;
    }

    if (!buf)
    {
        std::cout << "[access] [SSL] buf is nullptr.\n";
        return -1;
    }
    if (access(path, F_OK) != 0)
    {
        std::cout << "[access] [SSL] cert files is not exist\n";
        return -1;
    }

    BIO*           b;
    char *         Name = NULL, *header = NULL;
    unsigned char* data = NULL;

    int len = 0;
    b       = BIO_new_file(path, "rb");
    while (1)
    {
        X509* x;
        BIO*  bio_cert;
        x = PEM_read_bio_X509(b, NULL, NULL, NULL);
        if (x == NULL)
            break;

        // printf("......start.....\n");
        // X509_print_fp(stdout, x);
        // printf(".....end......\n");
        X509_NAME* subject = X509_get_subject_name(x);
        // printf("version : %lu\n", X509_get_version(x));
        // printf("subject_name : %lu\n", X509_subject_name_hash(x));
        // printf("issuer_name : %lu\n", X509_issuer_name_hash(x));
        char       data[8192] = {0x0};
        X509_NAME_oneline(subject, data, sizeof(data));
        std::cout << "[access] [SSL] client certificate SubjectName: " << data
                  << std::endl;

        bio_cert = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(bio_cert, x);
        // certificate info
        len = BIO_read(bio_cert, buf + len, buf_len - len);
        // std::cout << "[access] [SSL] CLIENT CERT: \n" << buf << std::endl;
        if (bio_cert)
        {
            BIO_free(bio_cert);
        }
        X509_free(x);
    }
    BIO_free(b);
}

int32_t EthAccessSocket::GetClientCert(const char* path, uint8_t* buf,
                                       int32_t buf_len)
{
    if (!path)
    {
        std::cout << "[access] [SSL] path is nullptr.\n";
        return -1;
    }

    if (!buf)
    {
        std::cout << "[access] [SSL] buf is nullptr.\n";
        return -1;
    }
    if (access(path, F_OK) != 0)
    {
        std::cout << "[access] [SSL] cert files is not exist\n";
        return -1;
    }

    X509* cert = NULL;
    FILE* fp   = NULL;
    // const int8_t PEM_read_str[10] = "1111";

    fp = fopen(path, "rb");
    if (fp == NULL)
    {
        std::cout << "[access] [SSL] client certificate open error\n";
        return -1;
    }

    // read certificate to x509 struct, passwd is 1111, it producted by produce
    // certificate
    // cert = PEM_read_X509(fp, NULL, NULL, const_cast<int8_t*>(PEM_read_str));
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (cert == NULL)
    {
        std::cout << "[access] [SSL] pem to x509 error\n";
        return -1;
    }
    X509_NAME* name     = NULL;
    BIO*       bio_cert = NULL;
#if 1
    // certificate subject name
    name = X509_get_subject_name(cert);
    X509_NAME_oneline(name, (char*)buf, buf_len);
    std::cout << "[access] [SSL] client certificate SubjectName: " << buf
              << std::endl;
    // std::memset(buf, 0, buf_len);
    X509_NAME_oneline(X509_get_issuer_name(cert), (char*)buf, buf_len);
    std::cout << "[access] [SSL] client certificate IssuerName: " << buf
              << std::endl;

    memset(buf, 0, sizeof(buf));
    bio_cert = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio_cert, cert);
    // certificate info
    auto len = BIO_read(bio_cert, buf, buf_len);
    std::cout << "[access] [SSL] CLIENT CERT: \n" << buf << std::endl;
    if (bio_cert)
    {
        BIO_free(bio_cert);
    }
#else

    // STACK_OF(X509_NAME) *sk2 = SSL_get_client_CA_list(cert);
    // if ((sk2 != NULL) && (sk_X509_NAME_num(sk2) > 0))
    // {
    //     BIO_printf(bio_cert, "---\nAcceptable client certificate CA
    //     names\n"); for (int i = 0; i < sk_X509_NAME_num(sk2); i++)
    //     {
    //         name = sk_X509_NAME_value(sk2, i);
    //         X509_NAME_oneline(name, (char*)buf, buf_len);
    //         BIO_write(bio_cert, buf, strlen((char*)buf));
    //         BIO_write(bio_cert, "\n", 1);
    //     }
    // }
    // else
    // {
    //     BIO_printf(bio_cert, "---\nNo client certificate CA names sent\n");
    // }

    // auto len = BIO_read(bio_cert, buf, buf_len);
    //  BIO_printf(bio_cert, "CLIENT CERT: \n%s", buf);

    // if (bio_cert)
    // {
    //     BIO_free(bio_cert);
    // }
#endif

    fclose(fp);

    if (cert)
    {
        X509_free(cert);
    }
    return len;
}

int EthAccessSocket::VerifyCb(int res, X509_STORE_CTX* xs)
{
    std::cout << "[access] [SSL] SSL VERIFY RESULT :" << res;
    // switch (xs->error)
    // {
    // case X509_V_ERR_UNABLE_TO_GET_CRL:
    //     std::cout << "[access] [SSL] NOT GET CRL\n";
    //     return 1;
    // default:
    //     break;
    // }

    return res;
}

// certificate chain
bool EthAccessSocket::LoadCertChainFromSharedMem(SSL_CTX*    context,
                                                 const char* cert_buffer)
{
    BIO* cbio = BIO_new_mem_buf((void*)cert_buffer, -1);
    if (!cbio)
        return false;

    X509_INFO* itmp;
    int        i;
    STACK_OF(X509_INFO)* inf = PEM_X509_INFO_read_bio(cbio, NULL, NULL, NULL);

    if (!inf)
    {
        BIO_free(cbio);
        return false;
    }

    /* Iterate over contents of the PEM buffer, and add certs. */
    bool first = true;
    for (i = 0; i < sk_X509_INFO_num(inf); i++)
    {
        std::cout << "x509 certificate chain num : " << i << std::endl;
        itmp = sk_X509_INFO_value(inf, i);
        if (itmp->x509)
        {
            /* First cert is server cert. Remaining, if any, are intermediate
             * certs. */
            if (first)
            {
                first = false;

                /*
                 * Set server certificate. Note that this operation increments
                 * the reference count, which means that it is okay for cleanup
                 * to free it.
                 */
                if (!SSL_CTX_use_certificate(context, itmp->x509))
                    goto Error;
                if (ERR_peek_error() != 0)
                    goto Error;

                /* Get ready to store intermediate certs, if any. */
                SSL_CTX_clear_chain_certs(context);
            }
            else
            {
                /* Add intermediate cert to chain. */
                if (!SSL_CTX_add0_chain_cert(context, itmp->x509))
                    goto Error;

                /*
                 * Above function doesn't increment cert reference count. NULL
                 * the info reference to it in order to prevent it from being
                 * freed during cleanup.
                 */
                itmp->x509 = NULL;
            }
        }
    }

    sk_X509_INFO_pop_free(inf, X509_INFO_free);
    BIO_free(cbio);

    return true;

Error:
    sk_X509_INFO_pop_free(inf, X509_INFO_free);
    BIO_free(cbio);

    return false;
}

// SSL_CTX_use_certificate_file
bool EthAccessSocket::LoadUseCertFromSharedMem(SSL_CTX*       ctx,
                                               const uint8_t* cert)
{
    /*read the cert and decode it*/
    BIO* certbio = BIO_new_mem_buf((void*)cert, -1);
    if (NULL == certbio)
    {
        return NULL;
    }
    X509* cert_x509 = PEM_read_bio_X509(certbio, NULL, NULL, NULL);
    if (NULL == cert_x509)
    {
        BIO_free(certbio);
        return NULL;
    }

    if (!SSL_CTX_use_certificate(ctx, cert_x509))
    {
        BIO_free(certbio);
        X509_free(cert_x509);
        return false;
    }

    BIO_free(certbio);
    X509_free(cert_x509);
    return true;
}

// SSL_CTX_use_PrivateKey_file
bool EthAccessSocket::LoadPrivateKeyFromSharedMem(SSL_CTX*       ctx,
                                                  const uint8_t* key)
{
    BIO* certbio = BIO_new_mem_buf((void*)key, -1);
    if (NULL == certbio)
    {
        return false;
    }

    EVP_PKEY* evpkey = PEM_read_bio_PrivateKey(certbio, NULL, NULL, NULL);
    if (NULL == evpkey)
    {
        BIO_free(certbio);
        return false;
    }

    if (!SSL_CTX_use_PrivateKey(ctx, evpkey))
    {
        BIO_free(certbio);
        EVP_PKEY_free(evpkey);
        return false;
    }

    EVP_PKEY_free(evpkey);
    BIO_free(certbio);
    return true;
}

// SSL_CTX_load_verify_locations
bool EthAccessSocket::LoadRootCertFromSharedMem(SSL_CTX*       context,
                                                const uint8_t* cert_buffer)
{
    BIO* cbio = BIO_new_mem_buf((void*)cert_buffer, -1);
    if (!cbio)
        return false;

    X509_INFO* itmp;
    STACK_OF(X509_INFO)* inf = PEM_X509_INFO_read_bio(cbio, NULL, NULL, NULL);

    if (!inf)
    {
        BIO_free(cbio);
        return false;
    }

    X509_STORE* ctx = SSL_CTX_get_cert_store(context);

    // Iterate over contents of the PEM buffer, and add certs.
    for (int i = 0; i < sk_X509_INFO_num(inf); i++)
    {
        itmp = sk_X509_INFO_value(inf, i);
        if (itmp->x509)
        {
            // Add intermediate cert to chain.
            if (!X509_STORE_add_cert(ctx, itmp->x509))
                goto Error;

            // Above function doesn't increment cert reference count. NULL the
            // info
            itmp->x509 = NULL;
        }
    }

    sk_X509_INFO_pop_free(inf, X509_INFO_free);
    BIO_free(cbio);

    return true;

Error:
    sk_X509_INFO_pop_free(inf, X509_INFO_free);
    BIO_free(cbio);

    return false;
}