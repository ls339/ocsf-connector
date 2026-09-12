"""Okta authentication: ``private_key_jwt`` client credentials, Bearer or DPoP.

An Okta-scoped service app authenticates with a signed JWT assertion, not a
client secret, and there is no refresh token: renewal means minting a new
assertion before the current access token expires (docs/SPEC.md §2.4).

A service app can also require Demonstrating Proof-of-Possession, and Okta's own
walkthrough tells the reader to turn that off on a new API Services app -- which
is why v1 supports both rather than asking a customer to weaken their app. That
is what shapes this seam: a DPoP proof is bound to one method and one URL and is
single-use, so authentication cannot be a token fetched once and reused. It is
:meth:`Authorizer.headers`, asked per request.

Nothing here logs or raises a key, an assertion, or a proof.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, cast

import httpx
import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

TOKEN_PATH = "/oauth2/v1/token"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

ASSERTION_LIFETIME_SECONDS = 300
"""Okta rejects an assertion whose ``exp`` is more than an hour out (§2.4). Five
minutes is enough for one request and keeps a leaked assertion nearly useless."""

RENEWAL_MARGIN = 0.8
"""Renew once this much of the token's lifetime has elapsed. Margin-based, not
401-driven: with no refresh token, a 401 is already too late (§2.4)."""

TOKEN_TIMEOUT_SECONDS = 30.0

SUPPORTED_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"})
"""What Okta accepts for both the client assertion and DPoP proofs (§2.4)."""


class AuthError(Exception):
    """Token minting failed, or Okta's answer did not match the configured mode.

    Carries Okta's ``error`` and description only -- never the assertion, the
    proof, the token, or any key material, because these reach logs.
    """


class Authorizer(Protocol):
    async def headers(self, method: str, url: str) -> dict[str, str]:
        """Authorization headers for exactly this request.

        Asked per request, not per stream: a DPoP proof commits to the method
        and URL it is sent with and may not be replayed, so a retry needs a new
        one. A Bearer implementation may ignore both arguments.
        """
        ...


@dataclass(frozen=True, slots=True)
class AccessToken:
    value: str
    token_type: str
    """``Bearer``, or ``DPoP`` when the app requires proof-of-possession."""
    renew_at: float
    """Instant on the credentials' clock at which to mint a replacement."""


@dataclass(slots=True)
class OktaClientCredentials:
    """Mints and caches an access token for an Okta service app (§2.4).

    ``private_key`` is PEM text loaded from the environment or a secrets manager
    at startup. It is never read from a config file in the repo, and ``kid``
    names which registered key signed the assertion, so two keys can be valid
    during a rollover.
    """

    org_url: str
    client_id: str
    private_key: str
    kid: str
    client: httpx.AsyncClient
    scopes: tuple[str, ...] = ("okta.logs.read",)
    algorithm: str = "RS256"
    clock: Callable[[], float] = time.time
    _token: AccessToken | None = field(default=None, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    def __post_init__(self) -> None:
        if self.algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"Okta does not accept {self.algorithm!r} (§2.4)")
        if not self.org_url.startswith("https://"):
            raise ValueError(f"org_url must be an https:// URL, got {self.org_url!r}")
        self.org_url = self.org_url.rstrip("/")

    @property
    def token_url(self) -> str:
        """The **org** authorization server's endpoint -- not ``/oauth2/default``."""
        return f"{self.org_url}{TOKEN_PATH}"

    async def token(self, proof: Callable[[str | None], str] | None = None) -> AccessToken:
        """The cached token, minting a new one once the margin has passed.

        ``proof`` builds a DPoP proof for the token request, taking the nonce
        Okta asked for (``None`` on the first attempt). Bearer callers omit it.
        The lock keeps a burst of requests to one mint rather than a stampede.
        """
        async with self._lock:
            cached = self._token
            if cached is not None and self.clock() < cached.renew_at:
                return cached
            minted = await self._mint(proof)
            self._token = minted
            return minted

    async def _mint(self, proof: Callable[[str | None], str] | None) -> AccessToken:
        form = {
            "grant_type": "client_credentials",
            "scope": " ".join(self.scopes),
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": self._assertion(),
        }
        headers = {"Accept": "application/json"}
        nonce: str | None = None
        for attempt in (1, 2):
            if proof is not None:
                headers["DPoP"] = proof(nonce)
            response = await self.client.post(
                self.token_url, data=form, headers=headers, timeout=TOKEN_TIMEOUT_SECONDS
            )
            # Okta answers a first DPoP token request with 400 use_dpop_nonce and
            # the nonce to use (§2.4). One retry, and only for that error.
            if attempt == 1 and proof is not None and response.status_code == 400:
                nonce = _nonce_challenge(response)
                if nonce is not None:
                    continue
            break

        if response.status_code != 200:
            raise _token_error(response)
        body = _json_object(response)
        try:
            value = str(body["access_token"])
        except KeyError:
            raise AuthError("Okta returned no access_token") from None
        expires_in = float(body.get("expires_in", 3600))
        return AccessToken(
            value=value,
            token_type=str(body.get("token_type", "Bearer")),
            renew_at=self.clock() + expires_in * RENEWAL_MARGIN,
        )

    def _assertion(self) -> str:
        issued = int(self.clock())
        return jwt.encode(
            {
                "iss": self.client_id,
                "sub": self.client_id,
                "aud": self.token_url,
                "iat": issued,
                "exp": issued + ASSERTION_LIFETIME_SECONDS,
                # Optional, and it makes the assertion single-use. A fresh one
                # per mint is the point: a replayed assertion is refused (§2.4).
                "jti": str(uuid.uuid4()),
            },
            self.private_key,
            algorithm=self.algorithm,
            headers={"kid": self.kid},
        )


@dataclass(slots=True)
class BearerAuth:
    """For an app with DPoP off: ``Authorization: Bearer`` and nothing else."""

    credentials: OktaClientCredentials

    async def headers(self, method: str, url: str) -> dict[str, str]:
        token = await self.credentials.token()
        if token.token_type.lower() != "bearer":
            raise AuthError(
                f"app returned a {token.token_type!r} token: it requires DPoP, use DpopAuth"
            )
        return {"Authorization": f"Bearer {token.value}"}


@dataclass(slots=True)
class DpopAuth:
    """For an app that requires proof-of-possession (§2.4).

    ``dpop_key`` is a PEM private key **separate from the client-authentication
    key**, per Okta's guidance. Its public half travels in every proof header;
    the private half never leaves this object.
    """

    credentials: OktaClientCredentials
    dpop_key: str
    algorithm: str = "RS256"
    clock: Callable[[], float] = time.time
    _public_jwk: dict[str, Any] = field(default_factory=dict, init=False)
    _nonce: str | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        if self.algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"Okta does not accept {self.algorithm!r} for DPoP proofs (§2.4)")
        self._public_jwk = _public_jwk(self.dpop_key, self.algorithm)

    async def headers(self, method: str, url: str) -> dict[str, str]:
        token = await self.credentials.token(self._token_proof)
        if token.token_type.lower() != "dpop":
            raise AuthError(
                f"app returned a {token.token_type!r} token: DPoP is off for it, use BearerAuth"
            )
        proof = self._proof(method=method, url=url, ath=_ath(token.value))
        return {"Authorization": f"DPoP {token.value}", "DPoP": proof}

    def _token_proof(self, nonce: str | None) -> str:
        # Okta renews the nonce every 24h and honors the old one for three days,
        # so a cached nonce usually spares the challenge round trip (§2.4).
        if nonce is not None:
            self._nonce = nonce
        return self._proof(method="POST", url=self.credentials.token_url, nonce=self._nonce)

    def _proof(
        self,
        *,
        method: str,
        url: str,
        ath: str | None = None,
        nonce: str | None = None,
    ) -> str:
        payload: dict[str, Any] = {
            "htm": method,
            "htu": _htu(url),
            "iat": int(self.clock()),
            # Unique per proof: a resource server must refuse a jti twice.
            "jti": secrets.token_urlsafe(16),
        }
        if ath is not None:
            payload["ath"] = ath
        if nonce is not None:
            payload["nonce"] = nonce
        return jwt.encode(
            payload,
            self.dpop_key,
            algorithm=self.algorithm,
            headers={"typ": "dpop+jwt", "jwk": self._public_jwk},
        )


def _htu(url: str) -> str:
    """The DPoP ``htu`` claim: RFC 9449 §4.2 says the target URI "without query
    and fragment parts".

    For a cursor that is everything before the ``?``. With the origin check in
    ``source.py`` it is one of only two places the connector reads a cursor's
    text, and like that one it reads no parameter (docs/SPEC.md §2.2).
    """
    return url.split("#", 1)[0].split("?", 1)[0]


def _ath(token: str) -> str:
    """Base64url SHA-256 of the access token, unpadded, binding proof to token."""
    digest = hashlib.sha256(token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _public_jwk(pem: str, algorithm: str) -> dict[str, Any]:
    """The public half of ``pem`` as a JWK, for the proof header.

    Guarded rather than trusted: a JWK carrying ``d`` would publish the private
    key to Okta and to anything between.
    """
    algo: RSAAlgorithm | ECAlgorithm = (
        RSAAlgorithm(RSAAlgorithm.SHA256)
        if algorithm.startswith("RS")
        else ECAlgorithm(ECAlgorithm.SHA256)
    )
    key = algo.prepare_key(pem)
    public = key.public_key() if hasattr(key, "public_key") else key
    exported: dict[str, Any] = algo.to_jwk(cast(Any, public), as_dict=True)
    jwk = {name: value for name, value in exported.items() if name != "key_ops"}
    private_members = {"d", "p", "q", "dp", "dq", "qi"} & set(jwk)
    if private_members:
        raise AuthError(
            f"refusing to publish private key material in a DPoP proof: {sorted(private_members)}"
        )
    return jwk


def _nonce_challenge(response: httpx.Response) -> str | None:
    """The nonce from a ``use_dpop_nonce`` refusal, if that is what this is."""
    body = _json_object(response)
    if body.get("error") != "use_dpop_nonce":
        return None
    nonce = response.headers.get("dpop-nonce")
    return str(nonce) if nonce is not None else None


def _token_error(response: httpx.Response) -> AuthError:
    body = _json_object(response)
    error = str(body.get("error", response.reason_phrase))
    description = body.get("error_description")
    detail = f"{error}: {description}" if description else error
    return AuthError(f"Okta token request failed (HTTP {response.status_code}) {detail}")


def _json_object(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}
