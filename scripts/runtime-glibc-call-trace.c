#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

/* Diagnostic-only libc call observer for the exact BonVoyage runtime image. */

#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define TRACE_PREFIX "BONVOYAGE_GLIBC_TRACE_V1"
#define TRACE_TEXT_LIMIT 512U
#define TRACE_LINE_LIMIT 4096U

static _Atomic int trace_state;
static _Thread_local bool trace_reentrant;

static bool trace_enabled(void) {
  int state = atomic_load_explicit(&trace_state, memory_order_acquire);
  if (state == 0) {
    const char *value = getenv("BONVOYAGE_GLIBC_TRACE");
    const int selected = value != NULL && strcmp(value, "1") == 0 ? 2 : 1;
    int expected = 0;
    (void)atomic_compare_exchange_strong_explicit(
        &trace_state, &expected, selected, memory_order_release,
        memory_order_relaxed);
    state = atomic_load_explicit(&trace_state, memory_order_acquire);
  }
  return state == 2;
}

static size_t append_text(char *output, size_t used, const char *value) {
  while (*value != '\0' && used < TRACE_LINE_LIMIT) {
    output[used++] = *value++;
  }
  return used;
}

static size_t append_hex(char *output, size_t used, const char *value) {
  static const char alphabet[] = "0123456789abcdef";
  if (value == NULL) {
    return append_text(output, used, "-");
  }
  for (size_t index = 0;
       index < TRACE_TEXT_LIMIT && value[index] != '\0' &&
       used + 2U <= TRACE_LINE_LIMIT;
       ++index) {
    const unsigned char byte = (unsigned char)value[index];
    output[used++] = alphabet[byte >> 4U];
    output[used++] = alphabet[byte & 0x0fU];
  }
  return used;
}

static void trace_event(const char *function, const char *argument,
                        void *return_address) {
  if (!trace_enabled() || trace_reentrant) {
    return;
  }
  trace_reentrant = true;

  const char *caller = NULL;
  Dl_info info;
  memset(&info, 0, sizeof(info));
  if (return_address != NULL && dladdr(return_address, &info) != 0) {
    caller = info.dli_fname;
  }

  char line[TRACE_LINE_LIMIT + 1U];
  size_t used = 0;
  used = append_text(line, used, TRACE_PREFIX);
  used = append_text(line, used, "\tfunction=");
  used = append_text(line, used, function);
  used = append_text(line, used, "\tcaller_hex=");
  used = append_hex(line, used, caller);
  used = append_text(line, used, "\targument_hex=");
  used = append_hex(line, used, argument);
  if (used < TRACE_LINE_LIMIT) {
    line[used++] = '\n';
  }
  (void)syscall(SYS_write, STDERR_FILENO, line, used);
  trace_reentrant = false;
}

static void *resolve_next(_Atomic(void *) *slot, const char *name) {
  void *resolved = atomic_load_explicit(slot, memory_order_acquire);
  if (resolved != NULL) {
    return resolved;
  }
  trace_reentrant = true;
  void *candidate = dlsym(RTLD_NEXT, name);
  trace_reentrant = false;
  if (candidate == NULL) {
    static const char message[] =
        "BONVOYAGE_GLIBC_TRACE_V1 resolver failure\n";
    (void)syscall(SYS_write, STDERR_FILENO, message, sizeof(message) - 1U);
    _exit(126);
  }
  void *expected = NULL;
  if (!atomic_compare_exchange_strong_explicit(
          slot, &expected, candidate, memory_order_release,
          memory_order_acquire)) {
    candidate = expected;
  }
  return candidate;
}

#define CALLER_ADDRESS()                                                        \
  __builtin_extract_return_addr(__builtin_return_address(0))

__attribute__((constructor)) static void trace_start(void) {
  trace_event("process_start", NULL, NULL);
}

__attribute__((destructor)) static void trace_stop(void) {
  trace_event("process_stop", NULL, NULL);
}

#define LOAD_FUNCTION(slot, name, type, target)                                  \
  do {                                                                            \
    void *symbol = resolve_next(&(slot), (name));                                  \
    _Static_assert(sizeof(symbol) == sizeof(target), "function pointer size");    \
    memcpy(&(target), &symbol, sizeof(target));                                    \
  } while (0)

FILE *fopen(const char *path, const char *mode) {
  (void)path;
  typedef FILE *(*function_type)(const char *, const char *);
  static _Atomic(void *) slot;
  function_type target;
  LOAD_FUNCTION(slot, "fopen", function_type, target);
  trace_event("fopen", mode, CALLER_ADDRESS());
  return target(path, mode);
}

FILE *fopen64(const char *path, const char *mode) {
  (void)path;
  typedef FILE *(*function_type)(const char *, const char *);
  static _Atomic(void *) slot;
  function_type target;
  LOAD_FUNCTION(slot, "fopen64", function_type, target);
  trace_event("fopen64", mode, CALLER_ADDRESS());
  return target(path, mode);
}

FILE *freopen(const char *path, const char *mode, FILE *stream) {
  typedef FILE *(*function_type)(const char *, const char *, FILE *);
  static _Atomic(void *) slot;
  function_type target;
  LOAD_FUNCTION(slot, "freopen", function_type, target);
  trace_event("freopen", mode, CALLER_ADDRESS());
  return target(path, mode, stream);
}

FILE *freopen64(const char *path, const char *mode, FILE *stream) {
  typedef FILE *(*function_type)(const char *, const char *, FILE *);
  static _Atomic(void *) slot;
  function_type target;
  LOAD_FUNCTION(slot, "freopen64", function_type, target);
  trace_event("freopen64", mode, CALLER_ADDRESS());
  return target(path, mode, stream);
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **result) {
  typedef int (*function_type)(const char *, const char *,
                               const struct addrinfo *, struct addrinfo **);
  static _Atomic(void *) slot;
  function_type target;
  LOAD_FUNCTION(slot, "getaddrinfo", function_type, target);
  trace_event("getaddrinfo", NULL, CALLER_ADDRESS());
  return target(node, service, hints, result);
}

struct hostent *gethostbyname(const char *name) {
  typedef struct hostent *(*function_type)(const char *);
  static _Atomic(void *) slot;
  function_type target;
  LOAD_FUNCTION(slot, "gethostbyname", function_type, target);
  trace_event("gethostbyname", NULL, CALLER_ADDRESS());
  return target(name);
}

struct hostent *gethostbyname2(const char *name, int family) {
  typedef struct hostent *(*function_type)(const char *, int);
  static _Atomic(void *) slot;
  function_type target;
  LOAD_FUNCTION(slot, "gethostbyname2", function_type, target);
  trace_event("gethostbyname2", NULL, CALLER_ADDRESS());
  return target(name, family);
}

int getnameinfo(const struct sockaddr *address, socklen_t address_length,
                char *host, socklen_t host_length, char *service,
                socklen_t service_length, int flags) {
  typedef int (*function_type)(const struct sockaddr *, socklen_t, char *,
                               socklen_t, char *, socklen_t, int);
  static _Atomic(void *) slot;
  function_type target;
  LOAD_FUNCTION(slot, "getnameinfo", function_type, target);
  trace_event("getnameinfo", NULL, CALLER_ADDRESS());
  return target(address, address_length, host, host_length, service,
                service_length, flags);
}
