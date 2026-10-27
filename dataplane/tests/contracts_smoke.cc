#include <cstdint>
#include <string>

#include "bonvoyage/v1/config.pb.h"

int main() {
  bonvoyage::v1::Snapshot snapshot;
  snapshot.set_schema_version(1U);
  snapshot.set_snapshot_id("phase-0-contract-smoke");
  snapshot.set_generation(1U);

  std::string serialized;
  if (!snapshot.SerializeToString(&serialized)) {
    return 1;
  }

  bonvoyage::v1::Snapshot decoded;
  if (!decoded.ParseFromString(serialized)) {
    return 2;
  }

  if (decoded.schema_version() != 1U ||
      decoded.snapshot_id() != "phase-0-contract-smoke" ||
      decoded.generation() != 1U) {
    return 3;
  }

  return 0;
}
