"""OTP top-list + send/auth-header helpers for test_mfa_bypass."""

from __future__ import annotations

from praetor import client
from praetor.tools._request_headers import apply_realistic_headers



# 100 most common OTP guesses. Ordered roughly by frequency in public dumps;
# the front of the list captures the highest hit rate per request.
_OTP_TOP_LIST: tuple[str, ...] = (
    "000000", "111111", "123456", "654321", "999999", "888888", "777777",
    "666666", "555555", "444444", "333333", "222222", "121212", "112233",
    "123123", "456456", "789789", "159753", "147258", "987654",
    "012345", "543210", "100000", "200000", "111222", "121314",
    # 4-digit fallbacks for short OTPs
    "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777",
    "8888", "9999", "1234", "4321", "1212", "1122", "1313", "1414",
    "1010", "2580", "0852", "9876", "5678", "8765",
    # Year-shaped
    "012024", "012025", "020224", "032024", "010101", "020202",
    # Date-shaped (DDMMYY heuristic — short list)
    "010190", "010191", "010192", "010193", "010194", "010195",
    "010196", "010197", "010198", "010199",
    # Pin-pad geometry
    "159357", "147369", "258369", "147741", "258852", "369963",
    "012321", "543212", "789987",
    # Repeating-digit shapes
    "010010", "101010", "020202", "131313", "242424", "353535",
    "464646", "575757", "686868", "797979", "808080", "909090",
)


async def _send(method: str, url: str, headers: dict, body: str = "",
                json_body: dict | None = None) -> dict:
    payload: dict = {"method": method, "url": url, "headers": headers,
                     "follow_redirects": False}
    if body:
        payload["body"] = body
    if json_body is not None:
        payload["json"] = json_body
    return await client.post("/api/http/curl", json=payload)


def _build_auth_headers(
    url: str, cookies: dict | None, bearer: str,
) -> dict[str, str]:
    h = apply_realistic_headers(url, {})
    if cookies:
        h["Cookie"] = "; ".join(
            f"{k}={str(v).replace(';', '%3B')}" for k, v in cookies.items())
    if bearer:
        h["Authorization"] = f"Bearer {bearer}"
    return h


