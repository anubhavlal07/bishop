"""Identity detector tests.

The numeric cases use real city coordinates so the expected distances can be
checked against any mapping tool rather than taken on trust.
"""

from __future__ import annotations

import pytest

from bishop.detectors.base import haversine_km
from bishop.detectors.identity import (
    IMPOSSIBLE_TRAVEL_KMH,
    account_manipulation,
    impossible_travel,
    mfa_fatigue,
    password_spray,
)
from tests.detectors.conftest import CITIES, alert, auth, proc


class TestHaversine:
    def test_london_to_new_york_is_about_5570_km(self):
        distance = haversine_km(*CITIES["london"], *CITIES["new_york"])
        assert 5540 < distance < 5600

    def test_identical_points_are_zero(self):
        assert haversine_km(51.5, -0.1, 51.5, -0.1) == pytest.approx(0.0, abs=1e-9)

    def test_antipodal_points_are_half_the_circumference(self):
        assert haversine_km(0.0, 0.0, 0.0, 180.0) == pytest.approx(20015.0, rel=0.001)

    def test_distance_is_symmetric(self):
        there = haversine_km(*CITIES["london"], *CITIES["singapore"])
        back = haversine_km(*CITIES["singapore"], *CITIES["london"])
        assert there == pytest.approx(back)


class TestImpossibleTravel:
    def test_london_to_singapore_in_ten_minutes_fires(self):
        result = impossible_travel(
            alert(
                auth_events=[
                    auth(0, city="london", source_ip="81.2.69.1"),
                    auth(600, city="singapore", source_ip="103.6.151.1"),
                ]
            )
        )
        assert result.fired
        assert result.score > 0.6
        assert result.facts["case"] == "travel"
        assert result.facts["implied_kmh"] > 60_000
        assert result.facts["distance_km"] > 10_000
        assert "T1078" in result.technique_hints

    def test_finding_points_at_the_events_it_rests_on(self):
        result = impossible_travel(
            alert(auth_events=[auth(0, city="london"), auth(600, city="singapore")])
        )
        assert result.facts["from_event_index"] == 0
        assert result.facts["to_event_index"] == 1
        assert result.facts["from_field"] == "auth_events[0].geo"
        assert result.facts["username"] == "alice"

    def test_two_different_accounts_are_never_compared(self):
        """The bug this guards: one alert carries several users' logins.

        Comparing alice-in-London against bob-in-Singapore manufactures travel
        that neither of them did.
        """
        result = impossible_travel(
            alert(
                auth_events=[
                    auth(0, username="alice", city="london"),
                    auth(600, username="bob", city="singapore"),
                ]
            )
        )
        assert not result.fired
        assert "no single account" in result.rationale
        # It looked and concluded, rather than having nothing to look at — the
        # difference decides whether the alert can be closed at all.
        assert result.examined

    def test_one_account_moving_is_still_caught_among_several_users(self):
        result = impossible_travel(
            alert(
                auth_events=[
                    auth(0, username="bob", city="new_york"),
                    auth(0, username="alice", city="london"),
                    auth(600, username="alice", city="singapore"),
                    auth(900, username="bob", city="new_york"),
                ]
            )
        )
        assert result.fired
        assert result.facts["username"] == "alice"

    def test_london_to_new_york_in_eight_hours_does_not_fire(self):
        # ~5,570 km in 8 h is about 700 km/h. That is a flight.
        result = impossible_travel(
            alert(auth_events=[auth(0, city="london"), auth(8 * 3600, city="new_york")])
        )
        assert not result.fired
        assert result.facts["pairs_compared"] == 1

    def test_same_metro_area_is_ignored(self):
        result = impossible_travel(
            alert(auth_events=[auth(0, city="london"), auth(60, city="london")])
        )
        assert not result.fired
        assert result.facts["pairs_compared"] == 0

    def test_short_gap_is_suppressed_as_a_network_artefact(self):
        """Two minutes cannot be travel at any speed, so it is not reported as travel.

        Firing here would put grounded evidence behind an explanation the
        detector itself disbelieves — and a VPN reconnect is the single most
        common cause of this pattern in a real estate.
        """
        result = impossible_travel(
            alert(auth_events=[auth(0, city="london"), auth(120, city="new_york")])
        )
        assert not result.fired
        assert result.score == 0.0
        suppressed = result.facts["suppressed_as_network_artefact"]
        assert len(suppressed) == 1
        assert suppressed[0]["case"] == "network_artefact"
        assert "VPN or proxy" in result.rationale

    def test_concurrent_sessions_fire_but_do_not_max_the_score(self):
        """A zero gap is not an infinite velocity — it is a division by zero.

        Duplicated events and disagreeing collector clocks both produce this,
        so it is capped well below the top of the range.
        """
        result = impossible_travel(
            alert(auth_events=[auth(0, city="london"), auth(0, city="sydney")])
        )
        assert result.fired
        assert result.facts["case"] == "concurrent_sessions"
        assert result.facts["implied_kmh"] is None
        assert result.score == 0.55

    def test_real_travel_outranks_a_concurrent_pair(self):
        result = impossible_travel(
            alert(
                auth_events=[
                    auth(0, city="london"),
                    auth(0, city="manchester"),
                    auth(600, city="singapore"),
                ]
            )
        )
        assert result.fired
        assert result.facts["case"] == "travel"

    def test_failed_logins_are_not_compared(self):
        result = impossible_travel(
            alert(
                auth_events=[
                    auth(0, city="london"),
                    auth(60, city="sydney", outcome="failure"),
                ]
            )
        )
        assert not result.fired
        assert "no single account" in result.rationale
        # It looked and concluded, rather than having nothing to look at — the
        # difference decides whether the alert can be closed at all.
        assert result.examined

    def test_events_out_of_order_still_compare_correctly(self):
        forwards = impossible_travel(
            alert(auth_events=[auth(0, city="london"), auth(600, city="singapore")])
        )
        backwards = impossible_travel(
            alert(auth_events=[auth(600, city="singapore"), auth(0, city="london")])
        )
        assert forwards.fired and backwards.fired
        assert forwards.facts["implied_kmh"] == backwards.facts["implied_kmh"]

    def test_missing_geolocation_is_a_miss_not_a_clear(self):
        result = impossible_travel(alert(auth_events=[auth(0), auth(600)]))
        assert not result.fired
        assert "geolocation" in result.rationale

    def test_score_rises_with_absurdity(self):
        mild = impossible_travel(
            alert(auth_events=[auth(0, city="london"), auth(3 * 3600, city="new_york")])
        )
        extreme = impossible_travel(
            alert(auth_events=[auth(0, city="london"), auth(1800, city="sydney")])
        )
        assert mild.fired and extreme.fired
        assert extreme.score > mild.score
        assert extreme.facts["implied_kmh"] > IMPOSSIBLE_TRAVEL_KMH


class TestMfaFatigue:
    def test_burst_of_denials_then_approval_fires(self):
        events = [auth(i * 30, outcome="mfa_denied") for i in range(6)]
        events.append(auth(200, outcome="mfa_success"))
        result = mfa_fatigue(alert(auth_events=events))
        assert result.fired
        assert result.score > 0.7
        assert result.facts["denials_before_approval"] >= 3
        assert "T1621" in result.technique_hints

    def test_denials_with_no_approval_still_fire_at_lower_confidence(self):
        events = [auth(i * 30, outcome="mfa_denied") for i in range(6)]
        result = mfa_fatigue(alert(auth_events=events))
        assert result.fired
        assert result.score == 0.5
        assert "held out" in result.rationale

    def test_a_single_denial_then_approval_is_ordinary(self):
        result = mfa_fatigue(
            alert(auth_events=[auth(0, outcome="mfa_denied"), auth(30, outcome="mfa_success")])
        )
        assert not result.fired

    def test_clean_approvals_do_not_fire(self):
        result = mfa_fatigue(
            alert(auth_events=[auth(0, outcome="mfa_success"), auth(90, outcome="mfa_success")])
        )
        assert not result.fired
        assert "no MFA prompts were denied" in result.rationale

    def test_too_few_events_is_a_miss(self):
        result = mfa_fatigue(alert(auth_events=[auth(0, outcome="mfa_denied")]))
        assert not result.fired
        assert "fewer than two" in result.rationale


class TestPasswordSpray:
    def test_wide_and_shallow_from_one_ip_fires(self):
        events = [
            auth(i * 5, username=f"user{i:02d}", outcome="failure", source_ip="203.0.113.9")
            for i in range(12)
        ]
        result = password_spray(alert(auth_events=events))
        assert result.fired
        assert result.facts["distinct_accounts"] == 12
        assert result.facts["max_attempts_per_account"] == 1
        assert "T1110.003" in result.technique_hints

    def test_a_success_after_the_spray_raises_the_score(self):
        events = [
            auth(i * 5, username=f"user{i:02d}", outcome="failure", source_ip="203.0.113.9")
            for i in range(12)
        ]
        without = password_spray(alert(auth_events=list(events)))
        events.append(auth(100, username="user03", outcome="success", source_ip="203.0.113.9"))
        with_hit = password_spray(alert(auth_events=events))
        assert with_hit.score > without.score
        assert with_hit.facts["compromised_accounts"] == ["user03"]

    def test_deep_and_narrow_is_brute_force_not_spraying(self):
        events = [
            auth(i * 5, username="alice", outcome="failure", source_ip="203.0.113.9")
            for i in range(20)
        ]
        result = password_spray(alert(auth_events=events))
        assert not result.fired
        assert "too narrow or too deep" in result.rationale

    def test_too_few_failures_is_a_miss(self):
        result = password_spray(alert(auth_events=[auth(0, username="a", outcome="failure")]))
        assert not result.fired
        assert "fewer than five" in result.rationale

    def test_attempts_are_grouped_by_source_ip(self):
        events = [
            auth(i, username=f"u{i}", outcome="failure", source_ip="198.51.100.1") for i in range(8)
        ]
        events += [
            auth(50 + i, username=f"v{i}", outcome="failure", source_ip="198.51.100.2")
            for i in range(3)
        ]
        result = password_spray(alert(auth_events=events))
        assert result.fired
        assert result.facts["source_ip"] == "198.51.100.1"
        assert result.facts["distinct_accounts"] == 8


class TestAccountManipulation:
    def test_adding_a_user_to_domain_admins_fires(self):
        result = account_manipulation(
            alert(process=proc("net.exe", 'net group "Domain Admins" attacker /add /domain'))
        )
        assert result.fired
        assert result.facts["observations"][0]["evidence_source"] == "command_line"
        assert "T1098" in result.technique_hints

    def test_local_administrators_addition_fires(self):
        result = account_manipulation(
            alert(process=proc("net1.exe", "net localgroup administrators bob /add"))
        )
        assert result.fired

    def test_a_directory_event_outweighs_a_command_line(self):
        """The domain controller wrote this one, not the attacker."""
        from_command_line = account_manipulation(
            alert(process=proc("net.exe", "net localgroup administrators bob /add"))
        )
        from_directory = account_manipulation(
            alert(
                raw={
                    "group_changes": [{"group": "Administrators", "member": "bob", "action": "add"}]
                }
            )
        )
        assert from_directory.fired and from_command_line.fired
        assert from_directory.score > from_command_line.score
        assert "directory's own change events" in from_directory.rationale

    def test_an_attacker_cannot_fabricate_a_finding_from_a_filename(self):
        """The evidence-fabrication case.

        An attacker who controls a command line can write anything into it,
        including text that looks like a privilege escalation. Requiring the
        *executable* to be a group-management tool means a document named after
        the command does not manufacture a finding against an innocent account.
        """
        result = account_manipulation(
            alert(
                process=proc(
                    "notepad.exe",
                    r'notepad.exe "C:\Users\bob\net localgroup administrators bob /add.txt"',
                )
            )
        )
        assert not result.fired
        assert result.facts["command_lines_skipped_wrong_binary"] == 1

    def test_creating_a_user_and_elevating_it_scores_higher_than_either_alone(self):
        one = account_manipulation(
            alert(process=proc("net.exe", "net localgroup administrators svc_backup /add"))
        )
        both = account_manipulation(
            alert(
                process=proc("net.exe", "net user svc_backup Passw0rd! /add"),
                child_processes=[proc("net.exe", "net localgroup administrators svc_backup /add")],
            )
        )
        assert both.score > one.score
        assert set(both.technique_hints) >= {"T1098", "T1136"}

    def test_ordinary_group_listing_does_not_fire(self):
        result = account_manipulation(
            alert(process=proc("net.exe", "net localgroup administrators"))
        )
        assert not result.fired

    def test_no_evidence_at_all_is_a_miss(self):
        result = account_manipulation(alert(process=proc("net.exe")))
        assert not result.fired
        assert "neither directory change events nor process command lines" in result.rationale
