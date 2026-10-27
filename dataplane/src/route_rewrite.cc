#include "bonvoyage/runtime/route_rewrite.hh"

#include <stdexcept>

namespace bonvoyage::runtime {

std::optional<std::string> rewrite_request_target(
    std::string_view original_target, std::string_view matched_prefix,
    const PathRewrite& rewrite, std::size_t max_target_bytes) {
  const auto query_offset = original_target.find('?');
  const auto original_path = original_target.substr(0U, query_offset);
  const auto raw_query = query_offset == std::string_view::npos
                             ? std::string_view{}
                             : original_target.substr(query_offset);

  std::string_view suffix;
  if (rewrite.operation == PathRewriteOperation::replace_prefix) {
    if (!original_path.starts_with(matched_prefix)) {
      throw std::invalid_argument(
          "request path does not start with the prepared route prefix");
    }
    suffix = original_path.substr(matched_prefix.size());
  }

  if (rewrite.value.size() > max_target_bytes ||
      suffix.size() > max_target_bytes - rewrite.value.size() ||
      raw_query.size() >
          max_target_bytes - rewrite.value.size() - suffix.size()) {
    return std::nullopt;
  }

  std::string result;
  result.reserve(rewrite.value.size() + suffix.size() + raw_query.size());
  result.append(rewrite.value);
  result.append(suffix);
  result.append(raw_query);
  return result;
}

}  // namespace bonvoyage::runtime
