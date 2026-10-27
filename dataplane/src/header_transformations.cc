#include "bonvoyage/runtime/header_transformations.hh"

#include <algorithm>
#include <limits>
#include <string_view>

namespace bonvoyage::runtime {
namespace {

char lower_ascii(char value) noexcept {
  if (value >= 'A' && value <= 'Z') {
    return static_cast<char>(value + ('a' - 'A'));
  }
  return value;
}

bool name_equal(std::string_view candidate,
                std::string_view lowercase_name) noexcept {
  return candidate.size() == lowercase_name.size() &&
         std::equal(candidate.begin(), candidate.end(), lowercase_name.begin(),
                    [](char left, char right) {
                      return lower_ascii(left) == right;
                    });
}

void remove_named_fields(std::vector<MutableHeader>& headers,
                         std::string_view lowercase_name) {
  std::erase_if(headers, [lowercase_name](const MutableHeader& header) {
    return name_equal(header.first, lowercase_name);
  });
}

bool within_limit(const std::vector<MutableHeader>& headers,
                  std::size_t maximum) noexcept {
  std::size_t total = 0U;
  for (const auto& [name, value] : headers) {
    constexpr std::size_t delimiter_bytes = 4U;  // ": " and CRLF.
    if (name.size() > maximum || value.size() > maximum ||
        delimiter_bytes > maximum || total > maximum - delimiter_bytes ||
        name.size() > maximum - total - delimiter_bytes) {
      return false;
    }
    total += name.size() + delimiter_bytes;
    if (value.size() > maximum - total) {
      return false;
    }
    total += value.size();
  }
  return total <= maximum;
}

}  // namespace

bool apply_header_mutations(std::vector<MutableHeader>& headers,
                            std::span<const HeaderMutation> mutations,
                            std::size_t max_bytes) {
  for (const auto& mutation : mutations) {
    switch (mutation.operation) {
      case HeaderMutationOperation::remove:
        remove_named_fields(headers, mutation.name);
        break;
      case HeaderMutationOperation::set:
        remove_named_fields(headers, mutation.name);
        headers.emplace_back(mutation.name, mutation.value);
        break;
      case HeaderMutationOperation::append: {
        std::string combined;
        for (const auto& [name, value] : headers) {
          if (!name_equal(name, mutation.name)) {
            continue;
          }
          if (!combined.empty()) {
            combined.append(", ");
          }
          combined.append(value);
        }
        remove_named_fields(headers, mutation.name);
        if (!combined.empty()) {
          combined.append(", ");
        }
        combined.append(mutation.value);
        headers.emplace_back(mutation.name, std::move(combined));
        break;
      }
    }
  }
  return within_limit(headers, max_bytes);
}

}  // namespace bonvoyage::runtime
