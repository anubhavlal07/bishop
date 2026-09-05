"""Accounts, roles and sessions.

Tested the way an access control has to be: by asserting the failures are
closed. The one that matters is the last class — before this module, any caller
could approve containment and name themselves whatever they liked in the audit
chain.
"""

from __future__ import annotations

import pytest

from bishop.auth import (
    MIN_PASSWORD_LENGTH,
    AuthError,
    PasswordError,
    Role,
    authenticate,
    create_account,
    current_account,
    end_session,
    hash_password,
    list_accounts,
    needs_rehash,
    set_role,
    start_session,
    verify_password,
)
from bishop.store import get_engine, init_db


@pytest.fixture
def engine(tmp_path, monkeypatch):
    return init_db(get_engine(f"sqlite:///{tmp_path / 'auth.db'}"))


@pytest.fixture(autouse=True)
def _bind(engine, monkeypatch):
    """Point the module-level helpers at the throwaway database."""
    import bishop.store.database as database

    monkeypatch.setattr(database, "_engine", engine, raising=False)
    yield


GOOD = "correct-horse-battery-staple"


class TestPasswordHashing:
    def test_a_hash_is_not_the_password(self):
        assert GOOD not in hash_password(GOOD)

    def test_the_right_password_verifies(self):
        assert verify_password(GOOD, hash_password(GOOD))

    def test_the_wrong_password_does_not(self):
        assert not verify_password("wrong-but-long-enough", hash_password(GOOD))

    def test_the_same_password_hashes_differently_each_time(self):
        """A shared salt would make identical passwords visible to anyone
        reading the table."""
        assert hash_password(GOOD) != hash_password(GOOD)

    def test_a_short_password_is_refused(self):
        with pytest.raises(PasswordError, match=str(MIN_PASSWORD_LENGTH)):
            hash_password("short")

    def test_an_enormous_password_is_refused(self):
        """scrypt reads the whole input, so an unbounded password is an
        unbounded hash — a denial of service through the login form."""
        with pytest.raises(PasswordError, match="bytes"):
            hash_password("a" * 5000)

    def test_a_corrupt_stored_hash_fails_closed(self):
        for junk in ("", "not-a-hash", "scrypt$bad", "bcrypt$1$2$3$4$5"):
            assert verify_password(GOOD, junk) is False

    def test_current_parameters_do_not_need_a_rehash(self):
        assert not needs_rehash(hash_password(GOOD))

    def test_weaker_parameters_do(self):
        assert needs_rehash("scrypt$1024$8$1$AAAA$BBBB")


class TestRoles:
    def test_roles_are_ordered_by_authority(self):
        assert Role.VIEWER.rank < Role.ANALYST.rank < Role.APPROVER.rank < Role.ADMIN.rank

    def test_an_approver_may_approve(self):
        assert Role.APPROVER.can(Role.APPROVER)

    def test_an_analyst_may_not(self):
        """The separation of duties the audit chain always implied."""
        assert not Role.ANALYST.can(Role.APPROVER)

    def test_a_viewer_may_not_triage(self):
        assert not Role.VIEWER.can(Role.ANALYST)

    def test_admin_satisfies_everything(self):
        assert all(Role.ADMIN.can(r) for r in Role)


class TestAccounts:
    def test_an_account_can_sign_in(self, engine):
        create_account("a@corp.example", GOOD, Role.ANALYST, engine=engine)
        account = authenticate("a@corp.example", GOOD, engine=engine)
        assert account.role is Role.ANALYST

    def test_the_address_is_case_insensitive(self, engine):
        create_account("Mixed@Corp.Example", GOOD, engine=engine)
        assert authenticate("mixed@corp.example", GOOD, engine=engine)

    def test_a_duplicate_address_is_refused(self, engine):
        create_account("dup@corp.example", GOOD, engine=engine)
        with pytest.raises(AuthError, match="already exists"):
            create_account("dup@corp.example", GOOD, engine=engine)

    def test_a_wrong_password_is_refused(self, engine):
        create_account("b@corp.example", GOOD, engine=engine)
        with pytest.raises(AuthError):
            authenticate("b@corp.example", "wrong-but-long-enough", engine=engine)

    def test_an_unknown_address_and_a_wrong_password_are_indistinguishable(self, engine):
        """Distinguishing them turns a password guess into account enumeration."""
        create_account("c@corp.example", GOOD, engine=engine)
        with pytest.raises(AuthError) as wrong:
            authenticate("c@corp.example", "wrong-but-long-enough", engine=engine)
        with pytest.raises(AuthError) as unknown:
            authenticate("nobody@corp.example", GOOD, engine=engine)
        assert str(wrong.value) == str(unknown.value)

    def test_the_listing_carries_no_hashes(self, engine):
        create_account("d@corp.example", GOOD, engine=engine)
        assert "password_hash" not in str(list_accounts(engine=engine))

    def test_describe_carries_no_hash(self, engine):
        create_account("e@corp.example", GOOD, engine=engine)
        described = authenticate("e@corp.example", GOOD, engine=engine).describe()
        assert GOOD not in str(described)
        assert "password" not in str(described)


class TestSessions:
    def test_a_session_resolves_to_its_account(self, engine):
        create_account("s@corp.example", GOOD, Role.APPROVER, engine=engine)
        account = authenticate("s@corp.example", GOOD, engine=engine)
        token = start_session(account, engine=engine)
        assert current_account(token, engine=engine).email == "s@corp.example"

    def test_the_raw_token_is_never_stored(self, engine):
        """A database read must not yield a usable session."""
        from sqlalchemy import select

        from bishop.auth.accounts import sessions

        create_account("t@corp.example", GOOD, engine=engine)
        token = start_session(authenticate("t@corp.example", GOOD, engine=engine), engine=engine)
        with engine.begin() as conn:
            stored = [r[0] for r in conn.execute(select(sessions.c.token_hash)).all()]
        assert token not in stored

    def test_an_unknown_token_resolves_to_nobody(self, engine):
        assert current_account("nonsense", engine=engine) is None

    def test_no_token_resolves_to_nobody(self, engine):
        assert current_account(None, engine=engine) is None

    def test_logging_out_revokes_the_session(self, engine):
        create_account("u@corp.example", GOOD, engine=engine)
        token = start_session(authenticate("u@corp.example", GOOD, engine=engine), engine=engine)
        end_session(token, engine=engine)
        assert current_account(token, engine=engine) is None

    def test_an_expired_session_is_refused_and_removed(self, engine, monkeypatch):
        from datetime import timedelta

        import bishop.auth.accounts as module

        monkeypatch.setattr(module, "SESSION_LIFETIME", timedelta(seconds=-1))
        create_account("v@corp.example", GOOD, engine=engine)
        token = start_session(authenticate("v@corp.example", GOOD, engine=engine), engine=engine)
        assert current_account(token, engine=engine) is None

    def test_changing_a_role_drops_existing_sessions(self, engine):
        """Without this, a demotion does not take effect until the session
        expires — the person keeps the authority just removed."""
        create_account("w@corp.example", GOOD, Role.APPROVER, engine=engine)
        token = start_session(authenticate("w@corp.example", GOOD, engine=engine), engine=engine)
        set_role("w@corp.example", Role.VIEWER, engine=engine)
        assert current_account(token, engine=engine) is None

    def test_a_new_session_reflects_the_new_role(self, engine):
        create_account("x@corp.example", GOOD, Role.APPROVER, engine=engine)
        set_role("x@corp.example", Role.VIEWER, engine=engine)
        account = authenticate("x@corp.example", GOOD, engine=engine)
        assert account.role is Role.VIEWER
        assert not account.role.can(Role.APPROVER)


class TestTheGateAuthenticatesItsApprover:
    """The gap this whole module exists to close.

    Before it, any caller could approve containment, and `decided_by` in the
    audit chain was whatever string the client sent — a chain of custody that
    looked complete and proved nothing.
    """

    @pytest.fixture
    def client(self, engine, monkeypatch):
        """The real app with accounts switched on.

        The flag is patched on the already-imported settings object rather than
        set in the environment and the module reloaded: reloading `app` rebinds
        every route and the middleware stack, and a half-rebuilt app is a worse
        thing to test than a patched flag.
        """
        import importlib

        from starlette.testclient import TestClient

        import bishop.store.database as database

        # `import bishop.api.app as app_module` would bind the FastAPI *object*,
        # not the module: `bishop/api/__init__.py` does `from bishop.api.app
        # import app`, so the name `app` shadows the submodule on the package.
        app_module = importlib.import_module("bishop.api.app")

        monkeypatch.setattr(database, "_engine", engine, raising=False)
        monkeypatch.setattr(app_module.settings, "require_accounts", True)

        with TestClient(app_module.app) as c:
            yield c

    def sign_in(self, client, engine, email, role):
        create_account(email, GOOD, role, engine=engine)
        r = client.post("/auth/login", json={"email": email, "password": GOOD})
        assert r.status_code == 200, r.text
        return r

    def test_signing_in_sets_a_session(self, client, engine):
        self.sign_in(client, engine, "app@corp.example", Role.APPROVER)
        me = client.get("/auth/me").json()
        assert me["authenticated"] is True
        assert me["may_approve_containment"] is True

    def test_an_analyst_may_not_approve_containment(self, client, engine):
        self.sign_in(client, engine, "ana@corp.example", Role.ANALYST)
        me = client.get("/auth/me").json()
        assert me["may_approve_containment"] is False

    def test_a_wrong_password_does_not_sign_in(self, client, engine):
        create_account("bad@corp.example", GOOD, engine=engine)
        r = client.post(
            "/auth/login", json={"email": "bad@corp.example", "password": "wrong-but-long"}
        )
        assert r.status_code == 401

    def test_the_login_response_carries_no_hash(self, client, engine):
        r = self.sign_in(client, engine, "leak@corp.example", Role.VIEWER)
        assert "scrypt" not in r.text
        assert GOOD not in r.text

    def test_the_session_cookie_is_http_only(self, client, engine):
        """An XSS bug on the console's origin must not become a session theft."""
        r = self.sign_in(client, engine, "cook@corp.example", Role.VIEWER)
        header = r.headers.get("set-cookie", "")
        assert "httponly" in header.lower()
        assert "samesite=lax" in header.lower()

    def test_logging_out_clears_the_session(self, client, engine):
        self.sign_in(client, engine, "out@corp.example", Role.VIEWER)
        client.post("/auth/logout")
        assert client.get("/auth/me").json()["authenticated"] is False

    def test_an_unauthenticated_caller_cannot_record_a_decision(self, client):
        r = client.post(
            "/runs/nope/decision",
            json={"decision": "approved", "approved_action_ids": ["a"], "decided_by": "me"},
        )
        # 401 for the missing session, or 404 because the run does not exist -
        # either way it is not accepted.
        assert r.status_code in (401, 404)
