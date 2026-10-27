#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

#include "bonvoyage/runtime/header_transformations.hh"

namespace {

using bonvoyage::runtime::HeaderMutation;
using bonvoyage::runtime::HeaderMutationOperation;
using bonvoyage::runtime::MutableHeader;

void require(bool condition, const char* message) {
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

std::size_t count(const std::vector<MutableHeader>& headers,
                  std::string_view name) {
  std::size_t result = 0U;
  for (const auto& [candidate, value] : headers) {
    (void)value;
    if (candidate == name) {
      ++result;
    }
  }
  return result;
}

std::string_view value(const std::vector<MutableHeader>& headers,
                       std::string_view name) {
  for (const auto& [candidate, candidate_value] : headers) {
    if (candidate == name) {
      return candidate_value;
    }
  }
  return {};
}

}  // namespace

int main() {
  std::vector<MutableHeader> headers{
      {"X-Set", "client"},
      {"x-append", "one"},
      {"X-Append", "two"},
      {"X-Remove", "drop"},
      {"x-unchanged", "keep"},
  };
  const std::vector<HeaderMutation> mutations{
      {HeaderMutationOperation::set, "x-set", "gateway"},
      {HeaderMutationOperation::append, "x-append", "three"},
      {HeaderMutationOperation::remove, "x-remove", {}},
      {HeaderMutationOperation::set, "x-added", "new"},
  };
  require(bonvoyage::runtime::apply_header_mutations(headers, mutations,
                                                      4096U),
          "bounded mutation list was rejected");
  require(count(headers, "x-set") == 1U && value(headers, "x-set") == "gateway",
          "set did not replace every case-insensitive field instance");
  require(count(headers, "x-append") == 1U &&
              value(headers, "x-append") == "one, two, three",
          "append did not combine existing values deterministically");
  require(count(headers, "X-Remove") == 0U,
          "remove retained a case-insensitive field instance");
  require(value(headers, "x-added") == "new",
          "set did not add an absent field");
  require(value(headers, "x-unchanged") == "keep",
          "an unrelated field changed");

  std::vector<MutableHeader> overflow{{"x-existing", "12345678"}};
  const std::vector<HeaderMutation> overflow_mutations{
      {HeaderMutationOperation::set, "x-added", "12345678"},
  };
  require(!bonvoyage::runtime::apply_header_mutations(
              overflow, overflow_mutations, 24U),
          "an oversized transformed field block was accepted");

  std::vector<MutableHeader> unchanged{{"x-small", "ok"}};
  require(bonvoyage::runtime::apply_header_mutations(unchanged, {}, 64U),
          "an in-bound empty mutation plan was rejected");
  require(unchanged.size() == 1U && unchanged.front().second == "ok",
          "an empty mutation plan changed the field list");

  std::cout << "header transformations passed\n";
  return 0;
}
