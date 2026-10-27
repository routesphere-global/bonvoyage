#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

// Keep scanner identity shared across formats, without changing image-carried
// producer records. The nghttp2 vendor/product follows the NVD CPE dictionary;
// its version is bound to the exact retained upstream source, not a wildcard.
export function staticMatchingCpe(record) {
  if (record.name === "nghttp2") {
    if (record.version !== "1.70.0" ||
        record.source?.commit !== "85e300c79fb6dbcfa9c1013215c8710c1c2cd3d2" ||
        record.source.archive_sha256 !== "aa317e2cf9dca6afa0aed68f8fad6ff303ec6982e25a78c75c0b65e2b9b3ded5" ||
        record.license?.spdx !== "MIT" || record.build?.linkage !== "static") {
      throw new Error("pinned static nghttp2 source identity required for CPE mapping");
    }
    return "cpe:2.3:a:nghttp2:nghttp2:1.70.0:*:*:*:*:*:*:*";
  }
  return record.matching?.cpe;
}

export function readDependencyRecords(directory, client = "seastar-reference") {
  if (!["seastar-reference", "llhttp-candidate"].includes(client)) {
    throw new Error("explicit supported upstream HTTP/1 client required");
  }
  const expected = new Map([
    ["abseil-20250512.1.json", "abseil"], ["c-ares-1.34.8.json", "c-ares"],
    ["libjwt-3.6.1.json", "libjwt"], ["llhttp-9.4.3.json", "llhttp"],
    ["nghttp2-1.70.0.json", "nghttp2"],
    ["opentelemetry-proto-1.11.0.json", "opentelemetry-proto"],
    ["re2-2025-11-05.json", "re2"], ["seastar-25.05.0.json", "seastar"],
  ]);
  const directoryInfo = fs.lstatSync(directory);
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
    throw new Error("regular declaration directory required");
  }
  const files = fs.readdirSync(directory).filter((name) => name.endsWith(".json")).sort();
  if (files.length !== expected.size || files.some((name) => !expected.has(name))) {
    throw new Error("missing/unknown runtime declaration file");
  }
  const names = new Set();
  return files.map((file) => {
    const target = path.join(directory, file);
    const info = fs.lstatSync(target);
    if (!info.isFile() || info.isSymbolicLink() || info.size <= 0 || info.size > 1024 * 1024) {
      throw new Error(`bounded regular dependency record required: ${file}`);
    }
    const record = JSON.parse(fs.readFileSync(target, "utf8"));
    if (record?.name !== expected.get(file) || names.has(record.name) ||
        typeof record.version !== "string" || file !== `${record.name}-${record.version}.json` ||
        typeof record.source?.commit !== "string" || !/^[a-f0-9]{40}$/.test(record.source.commit) ||
        typeof record.license?.spdx !== "string" || !record.license.spdx ||
        !["static", "generated C++ messages linked into the dataplane"].includes(record.build?.linkage)) {
      throw new Error(`incomplete/duplicate/mismatched dependency record: ${file}`);
    }
    names.add(record.name);
    if (record.name === "c-ares") {
      if (record.source.commit !== "c7a3138dcfe3bb0eaaf10c0c24c36dc66dc790ab" ||
          record.source.archive_sha256 !== "c222b6d681096f9444d2c4863d2c1174019e27cacca0a4a5c114d36dd7d7bf78" ||
          record.license.spdx !== "MIT" || record.build.linkage !== "static" ||
          record.matching?.cpe !== "cpe:2.3:a:c-ares_project:c-ares:1.34.8:*:*:*:*:*:*:*") {
        throw new Error("pinned static c-ares identity and source-established CPE required");
      }
    } else if (record.matching?.cpe !== undefined) {
      throw new Error(`unreviewed static CPE declaration: ${file}`);
    }
    staticMatchingCpe(record);
    const patches = [...(record.patches ?? []), ...(record.build.local_patches ?? [])];
    for (const patch of patches) {
      if (typeof (patch.path ?? patch.file) !== "string" ||
          typeof patch.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(patch.sha256)) {
        throw new Error(`incomplete carried patch record: ${file}`);
      }
    }
    return { file, record, patches };
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
const [sbomPath, dependencyDirectory, client] = process.argv.slice(2);

if (!sbomPath || !dependencyDirectory) {
  console.error(
    "usage: augment-runtime-sbom.mjs <cyclonedx.json> <dependency-directory> [seastar-reference|llhttp-candidate]",
  );
  process.exit(2);
}

const sbom = JSON.parse(fs.readFileSync(sbomPath, "utf8"));
if (sbom.bomFormat !== "CycloneDX" || !sbom.metadata?.component?.["bom-ref"]) {
  throw new Error("expected a CycloneDX SBOM with a root component");
}

const declarations = readDependencyRecords(dependencyDirectory, client);

// Cataloger identity alone is not proof of duplicate package ownership.
// Keep every generated entry and graph edge; Syft handles file overlap using
// the image's copied-file dpkg index before emitting either standard format.
sbom.components ??= [];

const directReferences = [];

for (const { file: dependencyFile, record, patches } of declarations) {
  const name = record.name;
  const version = record.version;
  if (!name || !version || !record.source?.commit || !record.license?.spdx) {
    throw new Error(`incomplete dependency record: ${dependencyFile}`);
  }

  const reference = `pkg:generic/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
  const component = {
    type: "library",
    "bom-ref": reference,
    name,
    version,
    scope: "required",
    purl: reference,
    licenses: [{ license: { id: record.license.spdx } }],
    externalReferences: [
      {
        type: "release-notes",
        url: record.source.release_url,
      },
      {
        type: "vcs",
        url: `${record.source.repository_url ?? record.source.release_url}#${record.source.commit}`,
      },
    ],
    properties: [
      { name: "bonvoyage:source:commit", value: record.source.commit },
      { name: "bonvoyage:source:tag", value: record.source.tag },
      { name: "bonvoyage:build:linkage", value: record.build?.linkage ?? "unknown" },
      { name: "bonvoyage:dependency:record", value: dependencyFile },
    ],
  };

  if (record.source.archive_sha256) {
    component.hashes = [
      { alg: "SHA-256", content: record.source.archive_sha256 },
    ];
    component.properties.push({
      name: "bonvoyage:hash:subject",
      value: "official source release archive",
    });
  }
  for (const carriedPatch of patches) {
    component.properties.push(
      {
        name: "bonvoyage:patch:path",
        value: carriedPatch.path ?? carriedPatch.file,
      },
      {
        name: "bonvoyage:patch:sha256",
        value: carriedPatch.sha256,
      },
      {
        name: "bonvoyage:patch:upstream-status",
        value: carriedPatch.upstream_status ?? "unknown",
      },
    );
  }
  const matchingCpe = staticMatchingCpe(record);
  if (matchingCpe) component.cpe = matchingCpe;

  const existingIndex = sbom.components.findIndex(
    (candidate) => candidate["bom-ref"] === reference,
  );
  if (existingIndex === -1) {
    sbom.components.push(component);
  } else {
    sbom.components[existingIndex] = component;
  }
  directReferences.push(reference);
}

const declaredNames = new Set(declarations.map(({ record }) => record.name));
for (const component of sbom.components) {
  if ((component.properties ?? []).some((p) => p.name === "bonvoyage:source:commit") &&
      !declaredNames.has(component.name)) {
    throw new Error(`unknown producer static component: ${component.name}`);
  }
}
for (const name of declaredNames) {
  if (sbom.components.filter((c) => c.name === name).length !== 1) {
    throw new Error(`duplicate or conflicting static component: ${name}`);
  }
}

sbom.components.sort((left, right) =>
  String(left["bom-ref"]).localeCompare(String(right["bom-ref"])),
);
sbom.dependencies ??= [];
const rootReference = sbom.metadata.component["bom-ref"];
const rootDependency = sbom.dependencies.find(
  (dependency) => dependency.ref === rootReference,
);
if (rootDependency) {
  rootDependency.dependsOn = [
    ...new Set([...(rootDependency.dependsOn ?? []), ...directReferences]),
  ].sort();
} else {
  sbom.dependencies.push({
    ref: rootReference,
    dependsOn: directReferences.sort(),
  });
}
for (const reference of directReferences) {
  if (!sbom.dependencies.some((dependency) => dependency.ref === reference)) {
    sbom.dependencies.push({ ref: reference, dependsOn: [] });
  }
}
sbom.dependencies.sort((left, right) => left.ref.localeCompare(right.ref));

sbom.metadata.properties ??= [];
sbom.metadata.properties.push({
  name: "bonvoyage:sbom:static-dependency-source",
  value: "security/dependencies",
});
fs.writeFileSync(sbomPath, `${JSON.stringify(sbom, null, 2)}\n`);
}
