// #include "eth_access_task.h"

// #include <thread>
// #include <unistd.h>

// void* eth_access_taskMain(void* params);

// int main()
// {
//     std::thread task(eth_access_taskMain, nullptr);
//     task.detach();
//     EthAccessTask::Instance()->Start();

//     while(1)
//     {
//         sleep(1);
//     }

// }

#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <thread>
#include <iomanip>

// #define ROOT_CERT_PATH "/home/lubow/work/src/test/Tls/server/pki/root_cert.crt"
// #define CLIENT_CERT_PATH "/home/lubow/work/src/test/Tls/server/pki/tbox_cert.crt"
// #define CLIENT_KEY_PATH "/home/lubow/work/src/test/Tls/server/pki/private_cert.key"


#define ROOT_CERT_PATH "/home/lubow/work/src/test/Tls/client/pki/ed25519/root_ed25519_cert.pem"
#define CLIENT_CERT_PATH  "/home/lubow/work/src/test/Tls/client/pki/ed25519/tbox_ed25519_cert.pem"
#define CLIENT_KEY_PATH "/home/lubow/work/src/test/Tls/client/pki/ed25519/private_ed25519_cert.key"


#define PREFERRED_SSL_CIPHER_LIST "ECDHE-ECDSA-AES128-GCM-SHA256"
// #define PREFERRED_SSL_CIPHER_LIST "RSA_WITH_AES_256_CBC_SHA256"

static void apps_ssl_info_callback(const SSL *s, int where, int ret)
{
    std::cout << "apps_ssl_info_callback *************** : ret : " << ret
              << std::endl;
    const char *str;
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

int create_socket(int port)
{
    int                socket_fd = -1;
    struct sockaddr_in addr;

    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

     int optval = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(socket_fd, 1) < 0)
    {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return socket_fd;
}

int verify_cb(int res, X509_STORE_CTX *xs)
{
    std::cout << "[access] [SSL] SSL VERIFY RESULT :" << res << std::endl;
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

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX          *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms(); /* Load cryptos, et.al. */
    SSL_load_error_strings();     /* Bring in and register error messages */

    method = TLSv1_2_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);

    // passwd is supplied to protect the private key,when you want to read key
    // SSL_CTX_set_default_passwd_cb_userdata(ctx,
    //                                        const_cast<int8_t*>(default_pw_str));

    // set cipher ,when handshake client will send the cipher list to server
    const long flags =
        SSL_OP_NO_COMPRESSION | SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
    SSL_CTX_set_options(ctx, flags);
    // SSL_CTX_set_cipher_list(ctx,"HIGH:MEDIA:LOW:!DH");
    // SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5");
    SSL_CTX_set_cipher_list(ctx,PREFERRED_SSL_CIPHER_LIST);
    // SSL_CTX_set_cipher_list(ctx,"AES128-SHA");

    // set verify ,when recive the server certificate and verify it
    // and verify_cb function will deal the result of verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);

    // sets the maximum depth for the certificate chain verification that shall
    // be allowed for ctx
    SSL_CTX_set_verify_depth(ctx, 10);

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    if (SSL_CTX_load_verify_locations(ctx, ROOT_CERT_PATH, nullptr) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    /* Set the key and cert */
    // if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_PATH, SSL_FILETYPE_PEM)
    // <=
    //     0)
    if (SSL_CTX_use_certificate_chain_file(ctx, CLIENT_CERT_PATH) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY_PATH, SSL_FILETYPE_PEM) <=
        0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    int      sock;
    SSL_CTX *ctx;

    /* Ignore broken pipe signals */
    signal(SIGPIPE, SIG_IGN);

    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(30504);

    /* Handle connections */
    while (1)
    {
        struct sockaddr_in addr;
        unsigned int       len = sizeof(addr);
        SSL               *ssl;
        const char         reply[] = "test\n";

        int client = accept(sock, (struct sockaddr *)&addr, &len);
        if (client < 0)
        {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
        }
        else
        {
            std::cout << "SSL connection using : " << SSL_get_cipher(ssl)
                      << std::endl;
            uint8_t buf[256] = {0x0};
            while (1)
            {
                memset(buf, 0, sizeof(buf));
                int len = SSL_read(ssl, buf, sizeof(buf));
                if (len <= 0)
                {
                    int err = ERR_get_error();
                    std::cout << "[access] [SSL] Connect error code: " << err
                              << ", string: " << ERR_error_string(err, NULL)
                              << std::endl;
                    std::cout << "[access] RecvSslMessage SSL_read error : "
                              << SSL_get_error(ssl, len);
                    break;
                }
                std::cout << "recv data len : " << len << std::endl;
                for (int i = 0; i < len; i++)
                {
                    std::cout << std::hex
                              << std::setiosflags(std::ios::uppercase)
                              << std::setfill('0') << std::setw(2)
                              << (int32_t)buf[i] << " " << std::dec;
                    ;
                }
                std::cout << std::endl;
            }
            // SSL_write(ssl, reply, strlen(reply));
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
}