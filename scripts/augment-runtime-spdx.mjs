#!/usr/bin/env node

import fs from "node:fs";
import { readDependencyRecords, staticMatchingCpe } from "./augment-runtime-sbom.mjs";

const [sbomPath, dependencyDirectory, client] = process.argv.slice(2);
if (!sbomPath || !dependencyDirectory) {
  console.error(
    "usage: augment-runtime-spdx.mjs <spdx.json> <dependency-directory> [seastar-reference|llhttp-candidate]",
  );
  process.exit(2);
}

const sbom = JSON.parse(fs.readFileSync(sbomPath, "utf8"));
if (sbom.spdxVersion !== "SPDX-2.3" || !Array.isArray(sbom.packages)) {
  throw new Error("expected an SPDX 2.3 JSON document with packages");
}

const root = sbom.packages.find(
  (candidate) => candidate.primaryPackagePurpose === "CONTAINER",
);
if (!root?.SPDXID) {
  throw new Error("SPDX document does not identify its container package");
}

const declarations = readDependencyRecords(dependencyDirectory, client);

for (const { file: dependencyFile, record, patches } of declarations) {
  if (
    !record.name ||
    !record.version ||
    !record.source?.commit ||
    !record.license?.spdx
  ) {
    throw new Error(`incomplete dependency record: ${dependencyFile}`);
  }

  const normalizedName = record.name.replace(/[^A-Za-z0-9.-]/g, "-");
  const packageId = `SPDXRef-Package-BonVoyage-${normalizedName}`;
  const purl = `pkg:generic/${encodeURIComponent(record.name)}@${encodeURIComponent(record.version)}`;
  const patchProvenance = patches.map((carriedPatch) => {
    return `${carriedPatch.path ?? carriedPatch.file} sha256=${carriedPatch.sha256}`;
  });
  const dependencyPackage = {
    name: record.name,
    SPDXID: packageId,
    versionInfo: record.version,
    supplier: "NOASSERTION",
    downloadLocation: record.source.archive_url ?? record.source.release_url,
    filesAnalyzed: false,
    sourceInfo: [
      `Statically linked from commit ${record.source.commit}`,
      `provenance record ${dependencyFile}`,
      ...patchProvenance.map((entry) => `carried patch ${entry}`),
    ].join("; "),
    licenseConcluded: record.license.spdx,
    licenseDeclared: record.license.spdx,
    copyrightText: "NOASSERTION",
    externalRefs: [
      {
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: purl,
      },
    ],
    primaryPackagePurpose: "LIBRARY",
  };
  const matchingCpe = staticMatchingCpe(record);
  if (matchingCpe) {
    dependencyPackage.externalRefs.push({ referenceCategory: "SECURITY", referenceType: "cpe23Type",
      referenceLocator: matchingCpe });
  }

  if (record.source.archive_sha256) {
    dependencyPackage.checksums = [
      {
        algorithm: "SHA256",
        checksumValue: record.source.archive_sha256,
      },
    ];
  }

  const existingIndex = sbom.packages.findIndex(
    (candidate) => candidate.SPDXID === packageId,
  );
  if (existingIndex === -1) {
    sbom.packages.push(dependencyPackage);
  } else {
    sbom.packages[existingIndex] = dependencyPackage;
  }

  sbom.relationships ??= [];
  const relationship = {
    spdxElementId: root.SPDXID,
    relatedSpdxElement: packageId,
    relationshipType: "CONTAINS",
  };
  if (
    !sbom.relationships.some(
      (candidate) =>
        candidate.spdxElementId === relationship.spdxElementId &&
        candidate.relatedSpdxElement === relationship.relatedSpdxElement &&
        candidate.relationshipType === relationship.relationshipType,
    )
  ) {
    sbom.relationships.push(relationship);
  }
}

const declaredNames = new Set(declarations.map(({ record }) => record.name));
for (const entry of sbom.packages) {
  if (entry.SPDXID?.startsWith("SPDXRef-Package-BonVoyage-") && !declaredNames.has(entry.name)) {
    throw new Error(`unknown producer static package: ${entry.name}`);
  }
}
for (const name of declaredNames) {
  if (sbom.packages.filter((p) => p.name === name).length !== 1) {
    throw new Error(`duplicate or conflicting static package: ${name}`);
  }
}
sbom.packages.sort((left, right) => left.SPDXID.localeCompare(right.SPDXID));
sbom.relationships.sort((left, right) =>
  [left.spdxElementId, left.relationshipType, left.relatedSpdxElement]
    .join("\u0000")
    .localeCompare(
      [right.spdxElementId, right.relationshipType, right.relatedSpdxElement]
        .join("\u0000"),
    ),
);
if (!sbom.creationInfo.creators.includes("Tool: RouteSphere SBOM augmenter")) {
  sbom.creationInfo.creators.push("Tool: RouteSphere SBOM augmenter");
}

fs.writeFileSync(sbomPath, `${JSON.stringify(sbom, null, 2)}\n`);
