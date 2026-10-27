import importlib.util
import json
import pathlib
import unittest
from unittest import mock


FIXTURE_PATH = pathlib.Path(__file__).with_name("fixture.py")
SPEC = importlib.util.spec_from_file_location("perf05_tls_boundary_fixture", FIXTURE_PATH)
assert SPEC is not None and SPEC.loader is not None
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class FixtureContractTest(unittest.TestCase):
    def test_config_has_exact_fixed_and_proxied_boundaries(self):
        config = fixture.build_config()
        routes = config["virtual_hosts"][0]["routes"]
        self.assertEqual(len(routes), 8)

        by_name = {route["name"]: route for route in routes}
        for size in fixture.PAYLOAD_BYTES:
            fixed = by_name[f"fixed-{size}"]
            proxied = by_name[f"proxied-{size}"]
            self.assertEqual(len(fixed["fixed_response"]["body"].encode("ascii")), size)
            self.assertNotIn("cluster", fixed)
            self.assertEqual(proxied["cluster"], "controlled-upstream")
            self.assertEqual(proxied["rewrite"]["path"], f"/payload/{size}")
            self.assertNotIn("fixed_response", proxied)

    def test_config_serialization_is_deterministic(self):
        first = json.dumps(fixture.build_config(), sort_keys=True, separators=(",", ":"))
        second = json.dumps(fixture.build_config(), sort_keys=True, separators=(",", ":"))
        self.assertEqual(first, second)

    def test_cluster_admission_covers_the_downstream_connection_cap(self):
        config = fixture.build_config()
        cluster = config["clusters"][0]
        downstream_cap = config["runtime_limits"][
            "max_downstream_connections_per_shard"
        ]

        self.assertEqual(
            cluster["max_connections_per_shard"],
            fixture.UPSTREAM_CONNECTIONS_PER_SHARD,
        )
        self.assertEqual(
            cluster["max_pending_requests_per_shard"],
            fixture.UPSTREAM_PENDING_REQUESTS_PER_SHARD,
        )
        self.assertGreaterEqual(
            cluster["max_connections_per_shard"]
            + cluster["max_pending_requests_per_shard"],
            downstream_cap,
        )

    def test_response_validation_distinguishes_route_actions(self):
        fixed = fixture.validate_response(
            "fixed",
            3,
            200,
            [("Content-Length", "3"), ("Content-Type", "application/octet-stream")],
            b"xxx",
        )
        proxied = fixture.validate_response(
            "proxied",
            3,
            200,
            [
                ("Content-Length", "3"),
                ("Content-Type", "application/octet-stream"),
                ("X-Upstream-Connection", "12345"),
            ],
            b"xxx",
        )
        self.assertFalse(fixed["upstream_marker_present"])
        self.assertTrue(proxied["upstream_marker_present"])

    def test_response_validation_rejects_wrong_payload_and_marker(self):
        headers = [("Content-Length", "3"), ("Content-Type", "application/octet-stream")]
        with self.assertRaises(fixture.FixtureError):
            fixture.validate_response("fixed", 3, 200, headers, b"xxy")
        with self.assertRaises(fixture.FixtureError):
            fixture.validate_response("proxied", 3, 200, headers, b"xxx")

    def test_transport_requires_tls13_aes_and_http11(self):
        valid = {
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "alpn": "http/1.1",
            "peer_dns_names": [fixture.HOSTNAME],
            "ca_verified": True,
            "hostname_verified": True,
        }
        fixture.validate_transport(valid)
        for field, value in (
            ("tls_version", "TLSv1.2"),
            ("cipher", "TLS_CHACHA20_POLY1305_SHA256"),
            ("alpn", None),
            ("peer_dns_names", []),
            ("ca_verified", False),
            ("hostname_verified", False),
        ):
            candidate = dict(valid)
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(fixture.FixtureError):
                fixture.validate_transport(candidate)

    def test_native_probe_separates_connect_address_from_tls_identity(self):
        expected_case = {"mode": "fixed", "payload_bytes": 15360}
        with mock.patch.object(fixture, "request_case", return_value=expected_case) as request:
            with mock.patch.object(fixture, "tls_context", side_effect=(object(), object())):
                with mock.patch.object(
                    fixture, "expect_tls_rejection", side_effect=("hostname", "issuer")
                ) as rejection:
                    result = fixture.run_native_probe(
                        "10.0.0.20", fixture.HOSTNAME, 8443,
                        "/tmp/ca.pem", "fixed", 15360
                    )

        request.assert_called_once_with(
            fixture.HOSTNAME, 8443, "/tmp/ca.pem", "fixed", 15360, "10.0.0.20"
        )
        self.assertEqual(
            rejection.call_args_list[0].args[0:2], ("wrong.example.test", 8443)
        )
        self.assertEqual(rejection.call_args_list[0].args[3], "10.0.0.20")
        self.assertEqual(rejection.call_args_list[1].args[0:2], (fixture.HOSTNAME, 8443))
        self.assertEqual(result["cases"], [expected_case])
        self.assertTrue(result["negative_probes"]["wrong_hostname_rejected"])

    def test_native_probe_rejects_cases_outside_frozen_matrix(self):
        with self.assertRaises(fixture.FixtureError):
            fixture.run_native_probe(
                "10.0.0.20", fixture.HOSTNAME, 8443, "/tmp/ca.pem", "other", 15360
            )
        with self.assertRaises(fixture.FixtureError):
            fixture.run_native_probe(
                "10.0.0.20", fixture.HOSTNAME, 8443, "/tmp/ca.pem", "fixed", 1024
            )


if __name__ == "__main__":
    unittest.main()
