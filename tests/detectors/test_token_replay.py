"""Tests for `token_replay`.

Written because the held-out set caught Bishop closing a refresh-token replay
as a false positive at 0.95 confidence. Both logins were from Dublin, ten
minutes apart, so `impossible_travel` cleared it correctly and nothing else had
jurisdiction — the evidence table came back empty and an intrusion read as
noise.

The discrimination that matters is the client, not the place. A browser session
does not become `python-requests`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from bishop.detectors.identity import token_replay
from bishop.schema import Alert, AuthEvent

BROWSER = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"
SCRIPT = "python-requests/2.31.0"

START = datetime(2026, 7, 9, 6, 2, tzinfo=UTC)


def login(
    *,
    minutes: int = 0,
    user_agent: str | None = BROWSER,
    ip: str | None = "192.0.2.31",
    username: str = "v.ramanathan",
    outcome: str = "success",
    mfa_method: str | None = None,
) -> AuthEvent:
    return AuthEvent(
        timestamp=START + timedelta(minutes=minutes),
        username=username,
        outcome=outcome,
        source_ip=ip,
        user_agent=user_agent,
        mfa_method=mfa_method,
    )


def alert_with(*events: AuthEvent) -> Alert:
    return Alert(
        alert_id="TOK-1",
        source="cloud-audit",
        rule_name="Access token used from a new autonomous system",
        detected_at=START,
        auth_events=list(events),
    )


class TestTheHandover:
    def test_a_browser_session_continuing_as_a_script_fires(self):
        result = token_replay(
            alert_with(
                login(),
                login(minutes=10, user_agent=SCRIPT, ip="198.51.100.240"),
            )
        )
        assert result.fired
        assert result.score >= 0.8
        assert result.technique_hints == ["T1550.001", "T1528"]

    def test_both_clients_are_reported_so_the_call_can_be_argued_with(self):
        result = token_replay(
            alert_with(login(), login(minutes=10, user_agent=SCRIPT, ip="198.51.100.240"))
        )
        assert result.facts["client_before"] == BROWSER
        assert result.facts["client_after"] == SCRIPT
        assert result.facts["seconds_between"] == 600
        assert result.facts["source_ip_changed"] is True

    def test_a_changed_address_scores_above_the_same_address(self):
        """A second tab is the innocent explanation, and a second tab keeps the IP."""
        same = token_replay(alert_with(login(), login(minutes=10, user_agent=SCRIPT)))
        moved = token_replay(
            alert_with(login(), login(minutes=10, user_agent=SCRIPT, ip="198.51.100.240"))
        )
        assert same.fired
        assert moved.score > same.score

    def test_a_dropped_mfa_factor_raises_it(self):
        """Re-authenticating produces a new factor. Its absence is what makes
        this reuse of a token rather than a second login."""
        kept = token_replay(
            alert_with(
                login(mfa_method="push"),
                login(minutes=10, user_agent=SCRIPT, mfa_method="push"),
            )
        )
        dropped = token_replay(
            alert_with(login(mfa_method="push"), login(minutes=10, user_agent=SCRIPT))
        )
        assert dropped.score > kept.score
        assert dropped.facts["mfa_factor_dropped"] is True

    def test_it_never_exceeds_its_cap(self):
        """One lexical read of one attacker-controlled field should not carry a
        verdict on its own."""
        result = token_replay(
            alert_with(
                login(mfa_method="push"),
                login(minutes=2, user_agent=SCRIPT, ip="198.51.100.240"),
            )
        )
        assert result.score <= 0.85

    @pytest.mark.parametrize(
        "agent",
        [
            "python-requests/2.31.0",
            "curl/8.4.0",
            "Go-http-client/2.0",
            "okhttp/4.12.0",
            "Mozilla/5.0 (Windows NT 10.0) WindowsPowerShell/5.1.19041.4291",
            "Boto3/1.34.0 Python/3.12.1",
            "axios/1.6.7",
        ],
    )
    def test_the_scripted_clients_an_attacker_actually_uses_are_covered(self, agent):
        assert token_replay(alert_with(login(), login(minutes=10, user_agent=agent))).fired


class TestOrdinaryCloudUseIsNotAnAttack:
    def test_two_browser_logins_do_not_fire(self):
        result = token_replay(alert_with(login(), login(minutes=10, ip="198.51.100.240")))
        assert not result.fired
        assert result.examined

    def test_a_script_that_was_always_a_script_does_not_fire(self):
        """A service account is a script from the start. The handover is the signal."""
        result = token_replay(
            alert_with(
                login(user_agent=SCRIPT),
                login(minutes=10, user_agent=SCRIPT, ip="198.51.100.240"),
            )
        )
        assert not result.fired
        assert result.examined

    def test_a_script_the_next_day_does_not_fire(self):
        """A client-class change over days is a person changing machines, not a
        session being replayed."""
        assert not token_replay(alert_with(login(), login(minutes=1500, user_agent=SCRIPT))).fired

    def test_the_two_clients_must_belong_to_one_account(self):
        """Comparing alice's browser against bob's script manufactures a
        handover that nobody performed."""
        result = token_replay(
            alert_with(
                login(username="alice"),
                login(minutes=10, username="bob", user_agent=SCRIPT),
            )
        )
        assert not result.fired

    def test_a_failed_login_is_not_a_session(self):
        result = token_replay(
            alert_with(login(), login(minutes=10, user_agent=SCRIPT, outcome="failure"))
        )
        assert not result.fired

    def test_the_script_must_come_after_the_browser(self):
        """The other order is a service account whose owner then signed in."""
        result = token_replay(
            alert_with(login(user_agent=SCRIPT), login(minutes=10, ip="198.51.100.240"))
        )
        assert not result.fired

    def test_events_out_of_order_are_sorted_before_comparison(self):
        """A detector must never assume the sensor sent events in order."""
        result = token_replay(
            alert_with(
                login(minutes=10, user_agent=SCRIPT, ip="198.51.100.240"),
                login(),
            )
        )
        assert result.fired
        assert result.facts["seconds_between"] == 600


class TestNothingToReadIsNotNothingToSee:
    def test_logins_without_a_user_agent_are_a_miss_not_a_clear(self):
        """Most identity providers send no user agent at all. Claiming the
        clients matched would be claiming a check nobody ran."""
        result = token_replay(
            alert_with(login(user_agent=None), login(minutes=10, user_agent=None))
        )
        assert not result.fired
        assert not result.examined

    def test_a_single_login_is_a_miss(self):
        result = token_replay(alert_with(login()))
        assert not result.fired
        assert not result.examined

    def test_an_alert_with_no_auth_events_is_a_miss(self):
        result = token_replay(alert_with())
        assert not result.fired
        assert not result.examined

    def test_an_unrecognised_client_does_not_count_as_a_browser(self):
        """An unknown string is unknown. Guessing it is a browser invents the
        first half of a handover."""
        result = token_replay(
            alert_with(login(user_agent="corp-sync/1.4"), login(minutes=10, user_agent=SCRIPT))
        )
        assert not result.fired


class TestPurity:
    def test_the_same_alert_gives_the_same_answer(self):
        alert = alert_with(login(), login(minutes=10, user_agent=SCRIPT, ip="198.51.100.240"))
        first, second = token_replay(alert), token_replay(alert)
        assert first.score == second.score
        assert first.facts == second.facts
