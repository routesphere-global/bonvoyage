#include <ares.h>
#include <ares_dns_record.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {
constexpr std::size_t allocation_cap = 1024 * 1024;
std::size_t largest_allocation{};
unsigned refused_allocations{};
unsigned failures{};

void observe(std::size_t bytes) {
  largest_allocation = std::max(largest_allocation, bytes);
  if (bytes > allocation_cap) {
    ++refused_allocations;
  }
}

void* capped_malloc(std::size_t bytes) {
  observe(bytes);
  return bytes > allocation_cap ? nullptr : std::malloc(bytes);
}

void* capped_realloc(void* memory, std::size_t bytes) {
  observe(bytes);
  return bytes > allocation_cap ? nullptr : std::realloc(memory, bytes);
}

void check(bool condition, const char* name) {
  if (!condition) {
    std::fprintf(stderr, "FAIL: %s\n", name);
    ++failures;
  }
}

// Refuse excessive allocations even on an accidentally regressed dependency.
// Rejection must come from validation, not from this test's allocation cap.
void parse_case(const char* name, const unsigned char* wire, std::size_t length,
                bool valid) {
  largest_allocation = 0;
  refused_allocations = 0;
  ares_dns_record_t* record = nullptr;
  const auto status = ares_dns_parse(wire, length, 0, &record);
  check(valid ? status == ARES_SUCCESS : status != ARES_SUCCESS, name);
  check(valid ? record != nullptr : record == nullptr, "record ownership");
  check(status != ARES_ENOMEM && refused_allocations == 0,
        "reject before allocation cap");
  check(largest_allocation <= 4096, "small response allocation bound");
  std::printf("case=%s wire_bytes=%zu status=%d max_allocation=%zu refused=%u\n",
              name, length, static_cast<int>(status), largest_allocation,
              refused_allocations);
  ares_dns_record_destroy(record);
}

void expand_case(const char* name, const std::vector<unsigned char>& wire,
                 std::size_t start, bool valid) {
  largest_allocation = 0;
  refused_allocations = 0;
  char* expanded = nullptr;
  long consumed = 0;
  const auto status = ares_expand_name(wire.data() + start, wire.data(),
                                       static_cast<int>(wire.size()),
                                       &expanded, &consumed);
  check(valid ? status == ARES_SUCCESS : status != ARES_SUCCESS, name);
  check(valid ? expanded != nullptr : expanded == nullptr, "name ownership");
  check(status != ARES_ENOMEM && refused_allocations == 0,
        "name rejection before allocation cap");
  if (valid && expanded != nullptr) {
    check(std::strlen(expanded) <= 255, "bounded expanded name");
  }
  std::printf("case=%s wire_bytes=%zu status=%d max_allocation=%zu refused=%u\n",
              name, wire.size(), status, largest_allocation, refused_allocations);
  ares_free_string(expanded);
}

std::vector<unsigned char> pointer_chain(unsigned hops) {
  std::vector<unsigned char> wire{0};
  std::size_t previous = 0;
  for (unsigned i = 0; i < hops; ++i) {
    const auto start = wire.size();
    wire.push_back(static_cast<unsigned char>(0xc0 | (previous >> 8)));
    wire.push_back(static_cast<unsigned char>(previous & 0xff));
    previous = start;
  }
  return wire;
}
}  // namespace

int main() {
  check(std::strcmp(ares_version(nullptr), "1.34.8") == 0,
        "exact pinned c-ares version");
  check(ares_threadsafety() == ARES_TRUE, "thread safety enabled");
  if (ares_library_init_mem(ARES_LIB_INIT_ALL, capped_malloc, std::free,
                            capped_realloc) != ARES_SUCCESS) {
    return 2;
  }
  const std::array<unsigned char, 17> valid = {
      0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1};
  parse_case("valid-empty-answer", valid.data(), valid.size(), true);
  parse_case("truncated-question", valid.data(), 12, false);
  auto counts = valid;
  std::fill(counts.begin() + 6, counts.begin() + 12, 0xff);
  parse_case("impossible-counts-truncated-question", counts.data(), 12, false);
  parse_case("impossible-counts-valid-question", counts.data(), counts.size(), false);
  auto no_question = counts;
  no_question[5] = 0;
  parse_case("impossible-counts-no-question", no_question.data(), 12, false);
  const std::array<const char*, 3> section_names = {
      "impossible-answer-count", "impossible-authority-count", "impossible-additional-count"};
  for (unsigned section = 0; section < section_names.size(); ++section) {
    auto section_counts = valid;
    section_counts[6 + section * 2] = 0xff;
    section_counts[7 + section * 2] = 0xff;
    parse_case(section_names[section], section_counts.data(), section_counts.size(), false);
  }

  const std::array<unsigned char, 33> answer = {
      0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1,
      0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1};
  parse_case("valid-compressed-a-answer", answer.data(), answer.size(), true);
  auto mixed_counts = answer;
  mixed_counts[9] = 1;
  mixed_counts[11] = 1;
  parse_case("combined-counts-exceed-wire", mixed_counts.data(), mixed_counts.size(), false);
  for (unsigned hops : {1U, 128U, 129U}) {
    const auto chain = pointer_chain(hops);
    expand_case(hops == 129 ? "over-limit-pointer-chain" : "valid-pointer-chain",
                chain, chain.size() - 2, hops <= 128);
  }
  expand_case("forward-pointer", {0xc0, 2, 0}, 0, false);
  expand_case("self-pointer", {0xc0, 0}, 0, false);
  std::vector<unsigned char> name;
  for (unsigned length : {63U, 63U, 63U, 61U}) {
    name.push_back(static_cast<unsigned char>(length));
    name.insert(name.end(), length, 'a');
  }
  name.push_back(0);
  expand_case("valid-maximum-wire-name", name, 0, true);
  name.pop_back();
  name.push_back(10);
  name.insert(name.end(), 10, 'b');
  name.push_back(0);
  expand_case("overlong-expanded-name", name, 0, false);
  // A rejected message must not poison subsequent parser state.
  parse_case("valid-after-rejections", answer.data(), answer.size(), true);
  ares_library_cleanup();
  std::printf("c_ares=1.34.8 failures=%u\n", failures);
  return failures == 0 ? 0 : 1;
}
