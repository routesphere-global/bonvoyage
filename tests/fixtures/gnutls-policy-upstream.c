#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;
static int listener_fd = -1;

static void stop_server(int signal_number) {
    (void)signal_number;
    running = 0;
    if (listener_fd >= 0) {
        close(listener_fd);
        listener_fd = -1;
    }
}

static int parse_port(const char* value) {
    char* end = NULL;
    errno = 0;
    const long port = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || port < 1 || port > 65535) {
        return -1;
    }
    return (int)port;
}

static bool send_all(gnutls_session_t session, const char* data, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        const ssize_t sent = gnutls_record_send(session, data + offset, size - offset);
        if (sent == GNUTLS_E_INTERRUPTED || sent == GNUTLS_E_AGAIN) {
            continue;
        }
        if (sent < 0) {
            return false;
        }
        offset += (size_t)sent;
    }
    return true;
}

static void serve_connection(int connection_fd, gnutls_certificate_credentials_t credentials) {
    gnutls_session_t session;
    int result = gnutls_init(&session, GNUTLS_SERVER);
    if (result < 0) {
        fprintf(stderr, "gnutls_init failed: %s\n", gnutls_strerror(result));
        return;
    }

    result = gnutls_set_default_priority(session);
    if (result >= 0) {
        result = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, credentials);
    }
    if (result < 0) {
        fprintf(stderr, "GnuTLS session setup failed: %s\n", gnutls_strerror(result));
        gnutls_deinit(session);
        return;
    }

    gnutls_transport_set_int(session, connection_fd);
    do {
        result = gnutls_handshake(session);
    } while (result == GNUTLS_E_INTERRUPTED || result == GNUTLS_E_AGAIN);

    if (result < 0) {
        fprintf(stderr, "TLS handshake rejected: %s\n", gnutls_strerror(result));
        gnutls_deinit(session);
        return;
    }

    char request[8192];
    size_t used = 0;
    while (used < sizeof(request) - 1) {
        const ssize_t received = gnutls_record_recv(
            session, request + used, sizeof(request) - 1 - used);
        if (received == GNUTLS_E_INTERRUPTED || received == GNUTLS_E_AGAIN) {
            continue;
        }
        if (received <= 0) {
            break;
        }
        used += (size_t)received;
        request[used] = '\0';
        if (strstr(request, "\r\n\r\n") != NULL) {
            break;
        }
    }

    static const char response[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: 16\r\n"
        "Connection: close\r\n"
        "\r\n"
        "xxxxxxxxxxxxxxxx";
    if (!send_all(session, response, sizeof(response) - 1)) {
        fprintf(stderr, "TLS response write failed\n");
    }
    (void)gnutls_bye(session, GNUTLS_SHUT_WR);
    gnutls_deinit(session);
}

int main(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s CERTIFICATE PRIVATE_KEY PORT\n", argv[0]);
        return 2;
    }
    const int port = parse_port(argv[3]);
    if (port < 0) {
        fprintf(stderr, "invalid port: %s\n", argv[3]);
        return 2;
    }

    int result = gnutls_global_init();
    if (result < 0) {
        fprintf(stderr, "gnutls_global_init failed: %s\n", gnutls_strerror(result));
        return 1;
    }

    gnutls_certificate_credentials_t credentials;
    result = gnutls_certificate_allocate_credentials(&credentials);
    if (result < 0) {
        fprintf(stderr, "credential allocation failed: %s\n", gnutls_strerror(result));
        gnutls_global_deinit();
        return 1;
    }
    result = gnutls_certificate_set_x509_key_file(
        credentials, argv[1], argv[2], GNUTLS_X509_FMT_PEM);
    if (result < 0) {
        fprintf(stderr, "certificate load failed: %s\n", gnutls_strerror(result));
        gnutls_certificate_free_credentials(credentials);
        gnutls_global_deinit();
        return 1;
    }

    signal(SIGTERM, stop_server);
    signal(SIGINT, stop_server);
    signal(SIGPIPE, SIG_IGN);

    listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listener_fd < 0) {
        perror("socket");
        gnutls_certificate_free_credentials(credentials);
        gnutls_global_deinit();
        return 1;
    }
    const int reuse_address = 1;
    (void)setsockopt(
        listener_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address, sizeof(reuse_address));

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port),
        .sin_addr = {.s_addr = htonl(INADDR_ANY)},
    };
    if (bind(listener_fd, (const struct sockaddr*)&address, sizeof(address)) < 0 ||
        listen(listener_fd, 32) < 0) {
        perror("bind/listen");
        close(listener_fd);
        gnutls_certificate_free_credentials(credentials);
        gnutls_global_deinit();
        return 1;
    }

    printf("GnuTLS policy fixture listening on port %d\n", port);
    fflush(stdout);
    while (running) {
        const int connection_fd = accept(listener_fd, NULL, NULL);
        if (connection_fd < 0) {
            if (!running || errno == EINTR) {
                continue;
            }
            perror("accept");
            break;
        }
        serve_connection(connection_fd, credentials);
        close(connection_fd);
    }

    if (listener_fd >= 0) {
        close(listener_fd);
    }
    gnutls_certificate_free_credentials(credentials);
    gnutls_global_deinit();
    return running ? 1 : 0;
}
