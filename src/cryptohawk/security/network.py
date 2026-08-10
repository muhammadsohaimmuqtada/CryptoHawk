from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass


class NetworkTargetError(ValueError):
    """Raised when a requested network target violates the outbound scan policy."""


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    hostname: str
    ip: str
    family: int
    socktype: int
    proto: int
    sockaddr: tuple


def _address_is_unsafe(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address.is_multicast or address.is_unspecified


def resolve_target(
    hostname: str,
    port: int,
    *,
    allow_private: bool = False,
) -> ResolvedTarget:
    """Resolve once, validate every answer, and return a pinned TCP destination.

    Validating every DNS answer prevents a hostname with mixed public/private answers from
    bypassing the default public-only policy. The caller must connect to ``sockaddr`` directly
    rather than resolving ``hostname`` a second time.
    """

    hostname = hostname.strip().rstrip(".")
    if not hostname:
        raise NetworkTargetError("hostname is empty")

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None

    if literal is not None:
        if _address_is_unsafe(literal):
            raise NetworkTargetError(f"unsafe target is blocked: {literal}")
        if not allow_private and not literal.is_global:
            raise NetworkTargetError(f"non-global target is blocked: {literal}")
        family = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
        if literal.version == 6:
            sockaddr: tuple = (str(literal), port, 0, 0)
        else:
            sockaddr = (str(literal), port)
        return ResolvedTarget(
            hostname=hostname,
            ip=str(literal),
            family=family,
            socktype=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
            sockaddr=sockaddr,
        )

    try:
        answers = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise NetworkTargetError(f"hostname resolution failed: {hostname}") from exc

    if not answers:
        raise NetworkTargetError(f"hostname resolution returned no addresses: {hostname}")

    resolved: list[ResolvedTarget] = []
    seen: set[tuple[int, str]] = set()
    for family, socktype, proto, _, sockaddr in answers:
        ip_text = str(sockaddr[0])
        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError as exc:
            raise NetworkTargetError(f"resolver returned an invalid address: {ip_text}") from exc

        if _address_is_unsafe(address):
            raise NetworkTargetError(
                f"hostname resolves to an unsafe address and is blocked: {ip_text}"
            )
        if not allow_private and not address.is_global:
            raise NetworkTargetError(
                "hostname resolves to a non-global address and is blocked: "
                f"{ip_text}"
            )

        key = (family, ip_text)
        if key in seen:
            continue
        seen.add(key)
        resolved.append(
            ResolvedTarget(
                hostname=hostname,
                ip=ip_text,
                family=family,
                socktype=socktype,
                proto=proto,
                sockaddr=sockaddr,
            )
        )

    if not resolved:
        raise NetworkTargetError(f"no usable TCP address resolved for: {hostname}")
    return resolved[0]
