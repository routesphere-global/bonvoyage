# The phase1 runner uses oha -z with one HTTP/1 request per connection.
# Only the exact end-of-test error, bounded by concurrency, is excluded from
# measured errors. Per-request timeouts and all other transport errors count.
def count_value:
  type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
def distribution:
  type == "object" and all(.[]; count_value);

if (.summary.total | type != "number") or
   (.summary.total | isfinite | not) or
   (.summary.total <= 0) or (.summary.total < $expected_duration) or
   ($expected_duration | type != "number" or . <= 0 or (isfinite | not)) or
   ($concurrency | count_value | not) or $concurrency == 0 or
   (.statusCodeDistribution | distribution | not) or
   (.errorDistribution | distribution | not) then
  error("invalid Phase 1 duration, concurrency, or request distributions")
elif (.statusCodeDistribution | keys | all(.[]; test("^[1-5][0-9][0-9]$")) | not) then
  error("invalid HTTP status in Phase 1 distribution")
else
  .summary.total as $duration |
  (.statusCodeDistribution["200"] // 0) as $accepted |
  ([.statusCodeDistribution[]] | add // 0) as $completed |
  (.errorDistribution["aborted due to deadline"] // 0) as $cancelled |
  ([.errorDistribution | to_entries[] |
    select(.key != "aborted due to deadline") | .value] | add // 0) as $transport |
  ($completed + $transport) as $measured |
  if $cancelled > $concurrency then
    error("deadline-end cancellations exceed Phase 1 concurrency")
  elif ($measured + $cancelled | count_value | not) then
    error("Phase 1 request count exceeds exact integer range")
  else {
    schema_version: 1,
    accepted_http_status: 200,
    duration_seconds: $duration,
    accepted_http_responses: $accepted,
    completed_http_responses: $completed,
    http_failures: ($completed - $accepted),
    transport_failures: $transport,
    deadline_end_cancellations: $cancelled,
    deadline_end_cancellation_limit: $concurrency,
    measured_requests: $measured,
    total_attempts: ($measured + $cancelled),
    successful_rps: ($accepted / $duration),
    error_rate: (if $measured > 0 then
      ($measured - $accepted) / $measured else 1 end)
  } end
end
