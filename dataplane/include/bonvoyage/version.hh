#pragma once

namespace bonvoyage {

/** Human-readable product name used in logs and diagnostics. */
inline constexpr const char* kProductName = "RouteSphere BonVoyage";

/** Stable executable/service identity. */
inline constexpr const char* kDataplaneName = "bonvoyage-dataplane";

/** Dataplane semantic version for the Phase 1 HTTP/1 runtime. */
inline constexpr const char* kDataplaneVersion = "0.2.0";

}  // namespace bonvoyage
