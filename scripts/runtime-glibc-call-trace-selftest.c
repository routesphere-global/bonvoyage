#define _GNU_SOURCE

#include <dlfcn.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  FILE *stream = fopen("/etc/os-release", "r");
  if (stream == NULL) {
    return 10;
  }
  if (fclose(stream) != 0) {
    return 11;
  }

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  struct addrinfo *result = NULL;
  if (getaddrinfo("localhost", "80", &hints, &result) != 0) {
    return 12;
  }
  if (result == NULL) {
    return 13;
  }

  char host[NI_MAXHOST];
  if (getnameinfo(result->ai_addr, result->ai_addrlen, host, sizeof(host),
                  NULL, 0, NI_NUMERICHOST) != 0) {
    freeaddrinfo(result);
    return 14;
  }
  freeaddrinfo(result);

  if (gethostbyname("localhost") == NULL) {
    return 15;
  }
  return 0;
}
