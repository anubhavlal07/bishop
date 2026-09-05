"""Tests for `kerberoasting`.

Written because the held-out set caught Bishop escalating a Kerberoasting alert
with nothing measured — a real intrusion arriving at a human with an empty
evidence table.

The discrimination that matters is rate and encryption. Every client requests
service tickets constantly; none requests forty in two minutes, and none asks
for RC4 on a domain that issues AES.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from bishop.detectors.identity import kerberoasting
from bishop.schema import Alert, Principal


def ticket_alert(**raw) -> Alert:
    return Alert(
        alert_id="KRB-1",
        source="windows-security",
        rule_name="Service ticket requests",
        detected_at=datetime(2026, 3, 14, tzinfo=UTC),
        principal=Principal(username="t.moreau", domain="CORP"),
        raw=raw,
    )


class TestTheHarvest:
    def test_bulk_rc4_requests_score_high(self):
        result = kerberoasting(
            ticket_alert(
                ticket_encryption="RC4-HMAC",
                service_tickets_requested=40,
                window_seconds=120,
            )
        )
        assert result.fired
        assert result.score >= 0.85
        assert result.technique_hints == ["T1558.003"]

    def test_the_rate_is_reported_so_it_can_be_argued_with(self):
        result = kerberoasting(
            ticket_alert(
                ticket_encryption="RC4-HMAC", service_tickets_requested=40, window_seconds=120
            )
        )
        assert result.facts["tickets_per_minute"] == 20.0
        assert result.facts["weak_encryption"] is True

    def test_rc4_scores_higher_than_the_same_volume_without_it(self):
        """The downgrade is what separates harvesting from a busy client."""
        weak = kerberoasting(
            ticket_alert(
                ticket_encryption="RC4-HMAC", service_tickets_requested=40, window_seconds=120
            )
        )
        strong = kerberoasting(
            ticket_alert(ticket_encryption="0x12", service_tickets_requested=40, window_seconds=120)
        )
        assert weak.score > strong.score

    @pytest.mark.parametrize("spelling", ["0x17", "rc4", "RC4-HMAC", "rc4_hmac_md5"])
    def test_the_encryption_spellings_sensors_use_are_covered(self, spelling):
        result = kerberoasting(
            ticket_alert(
                ticket_encryption=spelling, service_tickets_requested=40, window_seconds=120
            )
        )
        assert result.facts["weak_encryption"] is True

    def test_windows_field_names_are_read_as_well_as_normalised_ones(self):
        """Windows writes `TicketEncryptionType`; pipelines write snake_case."""
        result = kerberoasting(
            ticket_alert(TicketEncryptionType="0x17", tgs_requests=40, window_seconds=120)
        )
        assert result.fired
        assert result.facts["weak_encryption"] is True


class TestOrdinaryKerberosIsNotAnAttack:
    def test_a_handful_of_tickets_does_not_fire(self):
        """A client requests a ticket for a service it is about to use."""
        result = kerberoasting(
            ticket_alert(ticket_encryption="0x12", service_tickets_requested=4, window_seconds=60)
        )
        assert not result.fired
        assert result.examined

    def test_a_handful_with_rc4_still_does_not_fire(self):
        """Some legacy services genuinely still take RC4. Volume is the signal."""
        result = kerberoasting(
            ticket_alert(
                ticket_encryption="RC4-HMAC", service_tickets_requested=3, window_seconds=60
            )
        )
        assert not result.fired

    def test_an_alert_with_no_ticket_data_is_a_miss_not_a_clear(self):
        """Nothing to read is not read-and-found-nothing — the difference
        decides whether the alert can be closed at all."""
        result = kerberoasting(ticket_alert(some_other_field="x"))
        assert not result.fired
        assert not result.examined

    def test_an_unparseable_count_does_not_raise(self):
        """A sensor sending junk should fail the check, not the run."""
        result = kerberoasting(
            ticket_alert(ticket_encryption="RC4-HMAC", service_tickets_requested="lots")
        )
        assert not result.fired


class TestPurity:
    def test_the_same_alert_gives_the_same_answer(self):
        alert = ticket_alert(
            ticket_encryption="RC4-HMAC", service_tickets_requested=40, window_seconds=120
        )
        first, second = kerberoasting(alert), kerberoasting(alert)
        assert first.score == second.score
        assert first.facts == second.facts
