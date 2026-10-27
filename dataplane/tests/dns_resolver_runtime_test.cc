#include <ares.h>
#include <ares_dns_record.h>
#include <arpa/inet.h>

#include <chrono>
#include <coroutine>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/with_timeout.hh>
#include <seastar/net/api.hh>
#include <seastar/net/dns.hh>
#include <seastar/net/packet.hh>

namespace {
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;
using Address = seastar::net::inet_address;
using Record = std::unique_ptr<ares_dns_record_t,
                               decltype(&ares_dns_record_destroy)>;

constexpr auto attempt_timeout = 100ms;
// Seastar polls DNS on its timeout interval. Allow one extra polling interval
// and 40 ms scheduling slack, while still detecting c-ares' uncapped 250 ms floor.
constexpr auto observed_attempt_limit = 240ms;
constexpr auto lookup_watchdog = 2s;

void require(bool condition, std::string_view message) {
  if (!condition) {
    throw std::runtime_error(std::string(message));
  }
}

void require_ares(ares_status_t status, std::string_view operation) {
  if (status != ARES_SUCCESS) {
    throw std::runtime_error(std::string(operation) + ": " +
                             ares_strerror(static_cast<int>(status)));
  }
}

Address address(const char* text) {
  return Address(seastar::sstring(text));
}

double milliseconds(Clock::duration duration) {
  return std::chrono::duration<double, std::milli>(duration).count();
}

struct ReceivedQuery {
  std::string name;
  unsigned short id;
  Clock::time_point received;
};

class DnsFixture final {
 public:
  DnsFixture()
      : channel_(seastar::engine().net().make_bound_datagram_channel(
            seastar::socket_address(seastar::ipv4_addr("127.0.0.1", 0)))) {
    require(channel_.local_address().addr() == address("127.0.0.1") &&
                channel_.local_address().port() != 0,
            "DNS fixture must bind loopback on an ephemeral port");
  }

  void start() { loop_ = serve(); }

  seastar::net::dns_resolver::options options(
      std::chrono::milliseconds timeout) const {
    seastar::net::dns_resolver::options result;
    result.servers = std::vector<Address>{address("127.0.0.1")};
    result.udp_port = channel_.local_address().port();
    result.tcp_port = channel_.local_address().port();
    result.timeout = timeout;
    result.use_tcp_query = false;
    return result;
  }

  void answer(const char* ip, std::chrono::milliseconds delay = 0ms) {
    require(::inet_pton(AF_INET, ip, &answer_) == 1,
            "invalid fixture response address");
    reply_delay_ = delay;
    blackhole_ = false;
  }

  void blackhole() { blackhole_ = true; }
  const std::vector<ReceivedQuery>& queries() const { return queries_; }

  void check() const {
    if (failure_) {
      std::rethrow_exception(failure_);
    }
  }

  seastar::future<> wait_for_query(std::size_t previous_count) {
    const auto deadline = Clock::now() + lookup_watchdog;
    while (queries_.size() == previous_count) {
      check();
      require(Clock::now() < deadline,
              "resolver did not send a query to the loopback DNS fixture");
      co_await seastar::sleep(1ms);
    }
    check();
  }

  seastar::future<> stop() {
    stopping_ = true;
    channel_.shutdown_input();
    channel_.shutdown_output();
    co_await std::move(loop_);
    channel_.close();
    check();
  }

 private:
  seastar::future<> serve() {
    try {
      while (!stopping_) {
        auto datagram = co_await channel_.receive();
        if (stopping_) {
          break;
        }
        require(datagram.get_src().addr() == address("127.0.0.1"),
                "fixture received a non-loopback query");
        auto& packet = datagram.get_data();
        require(packet.len() > 0 && packet.len() <= 4096,
                "unexpected fixture query size");
        const auto* wire = reinterpret_cast<const unsigned char*>(
            packet.get_header(0, packet.len()));
        ares_dns_record_t* raw_query = nullptr;
        const auto parsed = ares_dns_parse(wire, packet.len(), 0, &raw_query);
        Record query(raw_query, ares_dns_record_destroy);
        require_ares(parsed, "parse fixture query");
        require(ares_dns_record_query_cnt(query.get()) == 1,
                "fixture requires one DNS question");
        const char* name = nullptr;
        ares_dns_rec_type_t type{};
        ares_dns_class_t qclass{};
        require_ares(ares_dns_record_query_get(query.get(), 0, &name, &type,
                                               &qclass),
                     "decode fixture question");
        require(name != nullptr && type == ARES_REC_TYPE_A &&
                    qclass == ARES_CLASS_IN,
                "fixture requires an IN/A question");
        require(queries_.size() < 64, "DNS query count escaped fixture bound");
        queries_.push_back({name, ares_dns_record_get_id(query.get()),
                            Clock::now()});
        if (blackhole_) {
          continue;
        }

        ares_dns_record_t* raw_response = nullptr;
        const auto created = ares_dns_record_create(
            &raw_response, ares_dns_record_get_id(query.get()),
            ARES_FLAG_QR | ARES_FLAG_AA | ARES_FLAG_RD | ARES_FLAG_RA,
            ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
        Record response(raw_response, ares_dns_record_destroy);
        require_ares(created, "create fixture response");
        require_ares(ares_dns_record_query_add(response.get(), name, type,
                                               qclass),
                     "copy fixture question");
        ares_dns_rr_t* rr = nullptr;
        require_ares(ares_dns_record_rr_add(&rr, response.get(),
                                            ARES_SECTION_ANSWER, name, type,
                                            qclass, 3600),
                     "create long-TTL A answer");
        require_ares(ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &answer_),
                     "set fixture A address");
        unsigned char* raw_wire = nullptr;
        std::size_t wire_length = 0;
        const auto written = ares_dns_write(response.get(), &raw_wire,
                                            &wire_length);
        std::unique_ptr<unsigned char, decltype(&ares_free_string)> encoded(
            raw_wire, ares_free_string);
        require_ares(written, "serialize fixture response");
        seastar::net::packet reply(
            reinterpret_cast<const char*>(encoded.get()), wire_length);
        if (reply_delay_ != 0ms) {
          co_await seastar::sleep(reply_delay_);
        }
        if (!stopping_) {
          co_await channel_.send(datagram.get_src(), std::move(reply));
        }
      }
    } catch (...) {
      if (!stopping_) {
        failure_ = std::current_exception();
      }
    }
  }

  seastar::net::datagram_channel channel_;
  seastar::future<> loop_{seastar::make_ready_future<>()};
  std::vector<ReceivedQuery> queries_;
  std::exception_ptr failure_;
  in_addr answer_{};
  std::chrono::milliseconds reply_delay_{};
  bool blackhole_{false};
  bool stopping_{false};
};

struct ResolverSession {
  explicit ResolverSession(const seastar::net::dns_resolver::options& options)
      : resolver(options) {}

  seastar::future<> close() {
    if (std::exchange(closed, true)) {
      return seastar::make_ready_future<>();
    }
    return resolver.close();
  }

  seastar::net::dns_resolver resolver;
  bool closed{false};
};

template <typename Check>
seastar::future<> with_resolver(DnsFixture& fixture,
                               std::chrono::milliseconds timeout,
                               Check check) {
  ResolverSession session(fixture.options(timeout));
  std::exception_ptr failure;
  try {
    co_await check(session);
  } catch (...) {
    failure = std::current_exception();
  }
  // Close before destroying the resolver, including watchdog/assertion paths.
  co_await session.close();
  if (failure) {
    std::rethrow_exception(failure);
  }
}

seastar::future<Address> lookup(ResolverSession& session, const char* name) {
  return seastar::with_timeout(
      Clock::now() + lookup_watchdog,
      session.resolver.resolve_name(seastar::sstring(name),
                                    Address::family::INET));
}

seastar::future<> cache_check(DnsFixture& fixture, ResolverSession& session) {
  const auto before = fixture.queries().size();
  fixture.answer("127.0.0.11");
  require(co_await lookup(session, "cache.bonvoyage.test.") ==
              address("127.0.0.11"),
          "first DNS answer was not decoded correctly");
  fixture.answer("127.0.0.12");
  require(co_await lookup(session, "cache.bonvoyage.test.") ==
              address("127.0.0.12"),
          "resolver reused a long-TTL cached answer");
  fixture.check();
  require(fixture.queries().size() == before + 2,
          "repeated hostname did not produce exactly two DNS queries");
  std::printf("case=cache-bypass queries=2 ttl_seconds=3600 changed_a=true\n");
}

seastar::future<> timeout_check(DnsFixture& fixture, ResolverSession& session,
                               bool warmed) {
  if (warmed) {
    // Three successful, nonzero-latency replies exercise c-ares' history-based
    // timeout calculation. Distinct names do not depend on cache behavior.
    const auto before_warmup = fixture.queries().size();
    fixture.answer("127.0.0.13", 60ms);
    for (const char* name : {"warm1.bonvoyage.test.",
                             "warm2.bonvoyage.test.",
                             "warm3.bonvoyage.test."}) {
      require(co_await lookup(session, name) == address("127.0.0.13"),
              "warm-up lookup returned the wrong address");
    }
    fixture.check();
    require(fixture.queries().size() == before_warmup + 3,
            "warm-up did not perform three successful DNS exchanges");
  }
  fixture.blackhole();
  const auto before = fixture.queries().size();
  const auto started = Clock::now();
  bool dns_timeout = false;
  try {
    (void)co_await lookup(session, "unanswered.bonvoyage.test.");
  } catch (const std::system_error& error) {
    dns_timeout = error.code().category() ==
                      seastar::net::dns::error_category() &&
                  error.code().value() == ARES_ETIMEOUT;
    if (!dns_timeout) {
      throw;
    }
  }
  const auto completed = Clock::now();
  const auto elapsed = completed - started;
  fixture.check();
  require(dns_timeout, "unanswered lookup did not fail with c-ares timeout");
  require(fixture.queries().size() == before + 3,
          "expected three attempts against the one loopback resolver");
  for (std::size_t i = before + 1; i < fixture.queries().size(); ++i) {
    const auto& previous = fixture.queries()[i - 1];
    const auto& current = fixture.queries()[i];
    require(current.name == previous.name && current.id == previous.id,
            "observed packets were not retries of the same DNS query");
    const auto gap = current.received - previous.received;
    std::printf("case=%s-timeout attempt_gap_ms=%.3f limit_ms=240\n",
                warmed ? "warm" : "cold", milliseconds(gap));
    require(gap >= 50ms && gap <= observed_attempt_limit,
            "DNS attempt timing escaped the 100 ms cap plus polling slack");
  }
  const auto final_gap = completed - fixture.queries().back().received;
  std::printf("case=%s-timeout final_attempt_ms=%.3f limit_ms=240\n",
              warmed ? "warm" : "cold", milliseconds(final_gap));
  require(final_gap >= 50ms && final_gap <= observed_attempt_limit,
          "final DNS attempt escaped the 100 ms cap plus polling slack");
  // This is a retrying lookup. Its total duration is deliberately not claimed
  // to be 100 ms; the watchdog only bounds the test's failure path.
  std::printf("case=%s-timeout attempts=3 lookup_ms=%.3f status=ARES_ETIMEOUT\n",
              warmed ? "warm" : "cold", milliseconds(elapsed));
}

seastar::future<> cancellation_check(DnsFixture& fixture,
                                    ResolverSession& session) {
  fixture.blackhole();
  const auto before = fixture.queries().size();
  auto pending = session.resolver.resolve_name(
      "cancel.bonvoyage.test.", Address::family::INET).then_wrapped(
      [](seastar::future<Address> result) {
        try {
          (void)result.get();
        } catch (const std::system_error& error) {
          if (error.code().category() == seastar::net::dns::error_category() &&
              error.code().value() == ARES_ECANCELLED) {
            return true;
          }
        } catch (...) {
        }
        return false;
      });
  co_await fixture.wait_for_query(before);
  require(!pending.available(), "cancellation test requires a live DNS query");
  const auto started = Clock::now();
  co_await session.close();
  require(co_await seastar::with_timeout(Clock::now() + 1s,
                                         std::move(pending)),
          "resolver.close did not complete the live query with ARES_ECANCELLED");
  const auto elapsed = Clock::now() - started;
  require(elapsed < 1s, "resolver.close waited for the five-second DNS timeout");
  const auto after_close = fixture.queries().size();
  co_await seastar::sleep(250ms);
  fixture.check();
  require(fixture.queries().size() == after_close,
          "closed resolver continued sending DNS queries");
  std::printf("case=close-live-query configured_attempt_ms=5000 close_ms=%.3f "
              "status=ARES_ECANCELLED\n", milliseconds(elapsed));
}

seastar::future<> run_checks() {
  require(std::string_view(ares_version(nullptr)) == "1.34.8",
          "runtime test requires pinned c-ares 1.34.8");
  require(ares_threadsafety() == ARES_TRUE,
          "runtime test requires c-ares thread-safety support");
  DnsFixture fixture;
  fixture.start();
  std::exception_ptr failure;
  try {
    co_await with_resolver(fixture, attempt_timeout,
        [&fixture](ResolverSession& session) {
          return cache_check(fixture, session);
        });
    for (bool warmed : {false, true}) {
      co_await with_resolver(fixture, attempt_timeout,
          [&fixture, warmed](ResolverSession& session) {
            return timeout_check(fixture, session, warmed);
          });
    }
    co_await with_resolver(fixture, 5s,
        [&fixture](ResolverSession& session) {
          return cancellation_check(fixture, session);
        });
  } catch (...) {
    failure = std::current_exception();
  }
  try {
    co_await fixture.stop();
  } catch (...) {
    if (!failure) {
      failure = std::current_exception();
    }
  }
  if (failure) {
    std::rethrow_exception(failure);
  }
}
}  // namespace

int main(int argc, char** argv) {
  // Override host retry settings in this process only; explicit loopback
  // servers and absolute query names keep the fixture off external DNS.
  require(::setenv("RES_OPTIONS", "attempts:3", 1) == 0,
          "could not set deterministic DNS attempt count");
  seastar::app_template app;
  return app.run(argc, argv, [] { return run_checks(); });
}
