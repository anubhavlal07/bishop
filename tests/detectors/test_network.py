"""Network detector tests.

Every series here is constructed deterministically. A beaconing test that used
random jitter would be a flaky test, and a flaky test on a detection primitive
is worse than no test.
"""

from __future__ import annotations

from bishop.detectors.base import coefficient_of_variation, median_absolute_deviation
from bishop.detectors.network import (
    _registrable_parts,
    beaconing,
    dns_exfiltration,
    outbound_volume,
)
from tests.detectors.conftest import alert, beacon_series, conn, dns


class TestSpreadMaths:
    def test_coefficient_of_variation_is_zero_for_a_flat_series(self):
        assert coefficient_of_variation([60.0] * 10) == 0.0

    def test_coefficient_of_variation_is_scale_free(self):
        small = coefficient_of_variation([10.0, 12.0, 8.0, 10.0])
        large = coefficient_of_variation([1000.0, 1200.0, 800.0, 1000.0])
        assert small == large

    def test_median_absolute_deviation_ignores_one_outlier(self):
        regular = [60.0] * 9
        with_outlier = [*regular, 100000.0]
        assert median_absolute_deviation(with_outlier) == 0.0
        assert coefficient_of_variation(with_outlier) > 2.0

    def test_short_series_return_zero_rather_than_raising(self):
        assert coefficient_of_variation([5.0]) == 0.0
        assert median_absolute_deviation([]) == 0.0


class TestRegistrableParts:
    def test_simple_domain(self):
        assert _registrable_parts("a.b.example.com") == ("example.com", ["a", "b"])

    def test_two_part_tld(self):
        assert _registrable_parts("data.example.co.uk") == ("example.co.uk", ["data"])

    def test_bare_domain_has_no_subdomains(self):
        assert _registrable_parts("example.com") == ("example.com", [])


class TestBeaconing:
    def test_metronomic_callbacks_fire(self):
        result = beaconing(alert(connections=beacon_series(12, 60.0, jitter=0.0, bytes_out=512)))
        assert result.fired
        assert result.score > 0.8
        assert result.facts["mean_interval_seconds"] == 60.0
        assert result.facts["uniform_payload_size"] is True
        assert "T1071.001" in result.technique_hints

    def test_deliberate_jitter_still_fires(self):
        result = beaconing(alert(connections=beacon_series(14, 300.0, jitter=0.1)))
        assert result.fired
        assert 0 < result.facts["jitter_percent"] <= 25

    def test_irregular_human_traffic_does_not_fire(self):
        gaps = [5.0, 900.0, 12.0, 3600.0, 45.0, 1800.0, 7.0, 240.0]
        elapsed = 0.0
        connections = []
        for gap in gaps:
            connections.append(conn(elapsed, host="www.example.com"))
            elapsed += gap
        result = beaconing(alert(connections=connections))
        assert not result.fired

    def test_a_missed_check_in_does_not_break_detection(self):
        connections = beacon_series(8, 60.0)
        elapsed = 8 * 60.0 + 7200.0
        for _ in range(5):
            connections.append(conn(elapsed, host="c2.example"))
            elapsed += 60.0
        result = beaconing(alert(connections=connections))
        assert result.fired
        assert result.facts["gaps_dropped_as_missed_checkins"] > 0
        assert result.facts["coefficient_of_variation"] > 2.0
        assert result.facts["trimmed_coefficient_of_variation"] == 0.0

    def test_too_few_connections_is_a_miss(self):
        result = beaconing(alert(connections=[conn(0), conn(60)]))
        assert not result.fired
        assert "at least 5" in result.rationale

    def test_destinations_are_scored_independently(self):
        noisy = [conn(i * 37.0 * (1 + i % 3), host="cdn.example") for i in range(9)]
        regular = beacon_series(10, 45.0, host="c2.example")
        result = beaconing(alert(connections=[*noisy, *regular]))
        assert result.fired
        assert result.facts["destination"] == "c2.example"


class TestDnsExfiltration:
    def test_encoded_subdomains_fire(self):
        queries = [
            dns(
                float(i),
                f"{'k4m2p9x7q1w8z3v6b0n5h2j7f4d1s8a3g6l9t2y5r8e1c4u7i0o3p6m9x2z5v8b1'[:60]}"
                f"{i:04d}.tunnel.example",
            )
            for i in range(20)
        ]
        result = dns_exfiltration(alert(dns_events=queries))
        assert result.fired
        assert result.facts["mean_entropy_bits_per_char"] > 3.2
        assert result.facts["unique_subdomains"] == 20
        assert "T1071.004" in result.technique_hints

    def test_ordinary_hostnames_do_not_fire(self):
        queries = [
            dns(float(i), host)
            for i, host in enumerate(
                [
                    "www.microsoft.com",
                    "login.microsoftonline.com",
                    "api.github.com",
                    "cdn.jsdelivr.net",
                    "mail.google.com",
                    "docs.google.com",
                ]
            )
        ]
        result = dns_exfiltration(alert(dns_events=queries))
        assert not result.fired

    def test_a_few_long_random_hostnames_are_not_enough(self):
        queries = [dns(float(i), f"a7f3k9{i}.cdn.example") for i in range(3)]
        result = dns_exfiltration(alert(dns_events=queries))
        assert not result.fired

    def test_too_few_queries_is_a_miss(self):
        result = dns_exfiltration(alert(dns_events=[dns(0, "a.example.com")]))
        assert not result.fired
        assert "too few" in result.rationale

    def test_bare_domains_carry_no_capacity(self):
        queries = [dns(float(i), "example.com") for i in range(5)]
        result = dns_exfiltration(alert(dns_events=queries))
        assert not result.fired
        assert "bare domain" in result.rationale


class TestOutboundVolume:
    def test_large_asymmetric_upload_fires(self):
        connections = [
            conn(float(i), host="drop.example", bytes_out=20_000_000, bytes_in=1_000)
            for i in range(5)
        ]
        result = outbound_volume(alert(connections=connections))
        assert result.fired
        assert result.facts["megabytes_out"] == 100.0
        assert "T1041" in result.technique_hints

    def test_ordinary_browsing_does_not_fire(self):
        connections = [
            conn(float(i), host="www.example.com", bytes_out=2_000, bytes_in=500_000)
            for i in range(5)
        ]
        result = outbound_volume(alert(connections=connections))
        assert not result.fired

    def test_small_upload_does_not_fire(self):
        connections = [conn(0.0, host="x.example", bytes_out=100_000, bytes_in=100)]
        result = outbound_volume(alert(connections=connections))
        assert not result.fired

    def test_missing_byte_counts_is_a_miss(self):
        result = outbound_volume(alert(connections=[conn(0.0)]))
        assert not result.fired
        assert "byte counts" in result.rationale
