"""Access tokens for the Okta source.

Okta-scoped management APIs accept only an OAuth 2.0 service app using client
credentials with ``private_key_jwt``. There is no refresh token, so "refresh"
means minting a new signed assertion before the current token expires
(docs/SPEC.md §2.4). That implementation sits beside this seam; the fetch path
depends only on the seam, so it is testable with a static token.
"""

from __future__ import annotations

from typing import Protocol


class TokenProvider(Protocol):
    async def token(self) -> str:
        """A currently valid access token carrying ``okta.logs.read``.

        Renews ahead of expiry rather than on a 401 (docs/SPEC.md §2.4), so the
        source asks for a token before every request and never for a fresh one.
        """
        ...
