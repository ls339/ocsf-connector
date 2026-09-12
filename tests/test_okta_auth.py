"""Okta authentication: the assertion, the token cache, and DPoP proofs.

Everything is synthetic (CLAUDE.md invariant 5): keys are generated in-process,
the org sits under the reserved ``.example`` TLD, and the client ID and token
values are invented.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ocsf_connector.sources.okta.auth import (
    RENEWAL_MARGIN,
    AuthError,
    BearerAuth,
    DpopAuth,
    OktaClientCredentials,
)

ORG = "https://synthetic.okta.example"
TOKEN_URL = f"{ORG}/oauth2/v1/token"
CLIENT_ID = "0oasynthetic0000001"
KID = "synthetic-signing-key-1"
ACCESS_TOKEN = "synthetic.access.token"
NONCE = "synthetic-nonce-0001"
CURSOR = f"{ORG}/api/v1/logs?after=synthetic-after-0001&since=2026-09-05T00%3A00%3A00Z"


def _pem_pair(key: Any) -> tuple[str, str]:
    private = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    public = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    return private, public


def _rsa_pair() -> tuple[str, str]:
    return _pem_pair(rsa.generate_private_key(public_exponent=65537, key_size=2048))


# The client-auth key and the DPoP key are deliberately different keys (§2.4).
CLIENT_KEY, CLIENT_PUBLIC = _rsa_pair()
DPOP_KEY, DPOP_PUBLIC = _rsa_pair()
EC_KEY, EC_PUBLIC = _pem_pair(ec.generate_private_key(ec.SECP256R1()))


def decode_assertion(request: httpx.Request) -> dict[str, Any]:
    """Claims of the posted client assertion.

    Expiry checking is off: the assertion is signed on the fake clock, and what
    matters here is the span between iat and exp, which the caller asserts.
    """
    claims: dict[str, Any] = jwt.decode(
        posted_form(request)["client_assertion"],
        CLIENT_PUBLIC,
        algorithms=["RS256"],
        audience=TOKEN_URL,
        options={"verify_exp": False},
    )
    return claims


class FakeClock:
    def __init__(self, now: float = 1_788_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as http:
        yield http


def credentials(
    client: httpx.AsyncClient, clock: FakeClock, **overrides: Any
) -> OktaClientCredentials:
    return OktaClientCredentials(
        org_url=ORG,
        client_id=CLIENT_ID,
        private_key=CLIENT_KEY,
        kid=KID,
        client=client,
        clock=clock,
        **overrides,
    )


def token_response(token_type: str = "Bearer", *, expires_in: int = 3600) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "token_type": token_type,
            "expires_in": expires_in,
            "access_token": ACCESS_TOKEN,
            "scope": "okta.logs.read",
        },
    )


def nonce_challenge() -> httpx.Response:
    """Okta's first answer to a DPoP token request (docs/SPEC.md §2.4)."""
    return httpx.Response(
        400,
        json={
            "error": "use_dpop_nonce",
            "error_description": "Authorization server requires nonce in DPoP proof.",
        },
        headers={"dpop-nonce": NONCE},
    )


def posted_form(request: httpx.Request) -> dict[str, str]:
    return {name: values[0] for name, values in parse_qs(request.content.decode()).items()}


def proof_from(request: httpx.Request, public_pem: str = DPOP_PUBLIC) -> tuple[Any, Any]:
    raw = request.headers["DPoP"]
    algorithm = jwt.get_unverified_header(raw)["alg"]
    return jwt.get_unverified_header(raw), jwt.decode(raw, public_pem, algorithms=[algorithm])


# --- the client assertion ---------------------------------------------------


async def test_the_client_assertion_carries_the_claims_okta_requires(
    client: httpx.AsyncClient, clock: FakeClock, respx_mock: respx.MockRouter
) -> None:
    """docs/SPEC.md §2.4: iss = sub = client ID, aud = the org token endpoint,
    and an exp Okta refuses if it is more than an hour out."""
    route = respx_mock.post(TOKEN_URL).mock(return_value=token_response())

    await BearerAuth(credentials(client, clock)).headers("GET", CURSOR)

    form = posted_form(route.calls.last.request)
    assert form["grant_type"] == "client_credentials"
    assert form["scope"] == "okta.logs.read"
    assert form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    assert jwt.get_unverified_header(form["client_assertion"])["kid"] == KID
    claims = decode_assertion(route.calls.last.request)
    assert claims["iss"] == claims["sub"] == CLIENT_ID
    assert claims["aud"] == TOKEN_URL
    assert 0 < claims["exp"] - claims["iat"] <= 3600


async def test_each_mint_signs_a_fresh_single_use_assertion(
    client: httpx.AsyncClient, clock: FakeClock, respx_mock: respx.MockRouter
) -> None:
    """A jti makes an assertion single-use, so reusing one would fail the second
    token request (docs/SPEC.md §2.4)."""
    route = respx_mock.post(TOKEN_URL).mock(return_value=token_response())
    auth = BearerAuth(credentials(client, clock))

    await auth.headers("GET", CURSOR)
    clock.advance(3600 * RENEWAL_MARGIN + 1)
    await auth.headers("GET", CURSOR)

    identifiers = {decode_assertion(call.request)["jti"] for call in route.calls}
    assert len(identifiers) == 2, "an assertion was replayed"


async def test_a_token_is_reused_until_the_renewal_margin(
    client: httpx.AsyncClient, clock: FakeClock, respx_mock: respx.MockRouter
) -> None:
    """Renew on a margin, not on a 401: there is no refresh token (§2.4)."""
    route = respx_mock.post(TOKEN_URL).mock(return_value=token_response(expires_in=3600))
    auth = BearerAuth(credentials(client, clock))

    await auth.headers("GET", CURSOR)
    clock.advance(3600 * RENEWAL_MARGIN - 1)
    await auth.headers("GET", CURSOR)
    assert route.call_count == 1, "renewed early"

    clock.advance(2)
    await auth.headers("GET", CURSOR)
    assert route.call_count == 2, "kept a token past its margin"


async def test_a_token_endpoint_failure_raises_without_leaking_the_assertion(
    client: httpx.AsyncClient, clock: FakeClock, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            401,
            json={"error": "invalid_client", "error_description": "Client authentication failed."},
        )
    )

    with pytest.raises(AuthError) as caught:
        await BearerAuth(credentials(client, clock)).headers("GET", CURSOR)

    message = str(caught.value)
    assert "invalid_client" in message
    assert "BEGIN PRIVATE KEY" not in message and "eyJ" not in message


# --- Bearer and DPoP disagreeing with the app -------------------------------


async def test_bearer_auth_sets_the_authorization_header(
    client: httpx.AsyncClient, clock: FakeClock, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post(TOKEN_URL).mock(return_value=token_response())

    headers = await BearerAuth(credentials(client, clock)).headers("GET", CURSOR)

    assert headers == {"Authorization": f"Bearer {ACCESS_TOKEN}"}


async def test_bearer_auth_refuses_a_dpop_bound_token(
    client: httpx.AsyncClient, clock: FakeClock, respx_mock: respx.MockRouter
) -> None:
    """The app has Require DPoP on. Say so, and name the fix."""
    respx_mock.post(TOKEN_URL).mock(return_value=token_response("DPoP"))

    with pytest.raises(AuthError, match="DpopAuth"):
        await BearerAuth(credentials(client, clock)).headers("GET", CURSOR)


async def test_dpop_auth_refuses_a_bearer_token(
    client: httpx.AsyncClient, clock: FakeClock, respx_mock: respx.MockRouter
) -> None:
    respx_mock.post(TOKEN_URL).mock(return_value=token_response("Bearer"))
    auth = DpopAuth(credentials(client, clock), dpop_key=DPOP_KEY, clock=clock)

    with pytest.raises(AuthError, match="BearerAuth"):
        await auth.headers("GET", CURSOR)


# --- DPoP proofs ------------------------------------------------------------


async def test_dpop_answers_the_nonce_challenge_then_reuses_the_nonce(
    client: httpx.AsyncClient, clock: FakeClock, respx_mock: respx.MockRouter
) -> None:
    """docs/SPEC.md §2.4: the first token request is refused with
    use_dpop_nonce; the retry carries the nonce. The nonce is then cached, so a
    later mint skips the extra round trip."""
    route = respx_mock.post(TOKEN_URL).mock(
        side_effect=[nonce_challenge(), token_response("DPoP"), token_response("DPoP")]
    )
    auth = DpopAuth(credentials(client, clock), dpop_key=DPOP_KEY, clock=clock)

    await auth.headers("GET", CURSOR)
    assert route.call_count == 2

    first, retry = (proof_from(call.request)[1] for call in route.calls)
    assert "nonce" not in first, "nothing to send before Okta names a nonce"
    assert retry["nonce"] == NONCE
    assert retry["htm"] == "POST" and retry["htu"] == TOKEN_URL
    assert "ath" not in retry, "the token request has no token to bind to yet"

    clock.advance(3600 * RENEWAL_MARGIN + 1)
    await auth.headers("GET", CURSOR)
    assert route.call_count == 3, "a cached nonce should avoid a second challenge"
    assert proof_from(route.calls.last.request)[1]["nonce"] == NONCE


async def test_a_dpop_proof_binds_the_request_method_url_and_token(
    client: httpx.AsyncClient, clock: FakeClock, respx_mock: respx.MockRouter
) -> None:
    """RFC 9449 §4.2: htu carries no query string, and ath is the base64url
    SHA-256 of the token. Each proof is single-use, so jti must not repeat."""
    respx_mock.post(TOKEN_URL).mock(side_effect=[nonce_challenge(), token_response("DPoP")])
    auth = DpopAuth(credentials(client, clock), dpop_key=DPOP_KEY, clock=clock)

    headers = await auth.headers("GET", CURSOR)
    again = await auth.headers("GET", CURSOR)

    assert headers["Authorization"] == f"DPoP {ACCESS_TOKEN}"
    proof = jwt.decode(headers["DPoP"], DPOP_PUBLIC, algorithms=["RS256"])
    assert proof["htm"] == "GET"
    assert proof["htu"] == f"{ORG}/api/v1/logs", "htu must drop the query"
    assert proof["ath"] == "-QewpHUCtn-84w5hJ66OomNbEVBLoB8lzguZDfCQXgM"

    reproof = jwt.decode(again["DPoP"], DPOP_PUBLIC, algorithms=["RS256"])
    assert proof["jti"] != reproof["jti"], "a proof was replayed"


async def test_a_dpop_proof_publishes_only_the_public_key(
    client: httpx.AsyncClient, clock: FakeClock, respx_mock: respx.MockRouter
) -> None:
    """The proof header carries a jwk so Okta can verify the signature. If any
    private member ever rode along, the key would be handed to everyone."""
    respx_mock.post(TOKEN_URL).mock(side_effect=[nonce_challenge(), token_response("DPoP")])
    auth = DpopAuth(credentials(client, clock), dpop_key=DPOP_KEY, clock=clock)

    headers = await auth.headers("GET", CURSOR)

    header = jwt.get_unverified_header(headers["DPoP"])
    assert header["typ"] == "dpop+jwt"
    assert set(header["jwk"]) == {"kty", "n", "e"}
    assert DPOP_KEY.split("\n")[1] not in headers["DPoP"]


async def test_an_ec_key_signs_dpop_proofs(
    client: httpx.AsyncClient, clock: FakeClock, respx_mock: respx.MockRouter
) -> None:
    """Okta accepts ES256 as well as RS256 for proofs (docs/SPEC.md §2.4)."""
    respx_mock.post(TOKEN_URL).mock(side_effect=[nonce_challenge(), token_response("DPoP")])
    auth = DpopAuth(credentials(client, clock), dpop_key=EC_KEY, algorithm="ES256", clock=clock)

    headers = await auth.headers("GET", CURSOR)

    header, proof = proof_from(httpx.Request("GET", CURSOR, headers=headers), EC_PUBLIC)
    assert header["alg"] == "ES256"
    assert set(header["jwk"]) == {"kty", "crv", "x", "y"}
    assert proof["htu"] == f"{ORG}/api/v1/logs"


@pytest.mark.parametrize("algorithm", ["HS256", "none", "RS128"])
async def test_an_algorithm_okta_does_not_accept_is_refused(
    client: httpx.AsyncClient, clock: FakeClock, algorithm: str
) -> None:
    with pytest.raises(ValueError, match="does not accept"):
        DpopAuth(credentials(client, clock), dpop_key=DPOP_KEY, algorithm=algorithm)
