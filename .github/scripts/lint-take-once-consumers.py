#!/usr/bin/env python3
"""Refuse a new consumer of the take-once protocol that nobody has read the contract for.

``DistributedCacheExtensions.TryRemoveAsync`` and ``TryGetAndRemoveAsync`` refuse for two reasons and
only one involves a competitor: another caller took it, or the claim EXPIRED mid-protocol - the second
on a single caller with nobody to lose to. A store call that fails after the removal is a third OUTCOME
rather than a third cause: it raises, and the caller is handed an exception instead of an answer.

Every consumer that wrote its own ``<returns>`` from the shape of the call - rather than from that
contract - said "a concurrent request already claimed it", and an operator told a second request was the
cause goes looking for a second node while the single-caller case is exactly the one that never produces
one.

Prose cannot be checked here without crying wolf: "concurrent" is a legitimate word in most of these
files, and a detector with false positives trains everyone to wave it away. What CAN be checked exactly
is the REACH - who consumes the protocol at all. This list is the answer, and a change to it fails until
somebody re-reads the contract and updates it deliberately.

Usage: ``lint-take-once-consumers.py``; it walks the tracked ``.cs`` files.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

#: Both ways in. The two extension methods by name, and the flag that routes a read through the same
#: protocol one layer up - `IEntityStorage.GetAsync(..., removeOnRetrieval: true)` and
#: `IAuthorizationRequestStorage.TryGetAsync(..., shouldRemove: true)`. A name grep alone was blind to
#: the second, and files describing this refusal reach it only that way.
CALL = re.compile(
    r"\b(TryRemoveAsync|TryGetAndRemoveAsync)\b"
    r"|\b(removeOnRetrieval|shouldRemove)\s*:\s*true\b")

DECLARING = "src/Abblix.Utils/DistributedCacheExtensions.cs"

#: Every file in `src/` that reaches the take-once protocol, by either route, as of the sweep for issue
#: 455. Each was checked against the contract rather than against the call's shape, and adding a name
#: here is the moment to read that contract.
#:
#: This is what the checker CAN see. A caller reaching the protocol through some third wrapper, named
#: neither way, is outside it - so the list is the reach of the two routes above rather than a proof that
#: nothing else redeems.
KNOWN = {
    "src/Abblix.Oidc.Server/Endpoints/Token/Grants/BackChannelAuthenticationGrantHandler.cs",
    "src/Abblix.Oidc.Server/Endpoints/Token/Grants/DeviceCodeGrantHandler.cs",
    "src/Abblix.Oidc.Server/Features/BackChannelAuthentication/AuthenticationNotifiers/PushModeCompletionHandler.cs",
    "src/Abblix.Oidc.Server/Features/BackChannelAuthentication/BackChannelRequestStorage.cs",
    "src/Abblix.Oidc.Server/Features/BackChannelAuthentication/GrantProcessors/PingModeGrantProcessor.cs",
    "src/Abblix.Oidc.Server/Features/BackChannelAuthentication/GrantProcessors/PollModeGrantProcessor.cs",
    "src/Abblix.Oidc.Server/Features/BackChannelAuthentication/Interfaces/IBackChannelRequestStorage.cs",
    "src/Abblix.Oidc.Server/Features/DeviceAuthorization/DeviceAuthorizationStorage.cs",
    "src/Abblix.Oidc.Server/Features/DeviceAuthorization/Interfaces/IDeviceAuthorizationStorage.cs",
    "src/Abblix.Oidc.Server/Features/Storages/DistributedCacheStorage.cs",
    "src/Abblix.Oidc.Server/Features/PushedAuthorization/PushedAuthorizationRequestProcessorDecorator.cs",
    "src/Abblix.Oidc.Server/Features/Storages/AuthorizationCodeService.cs",
}

CONTRACT = (
    "A caller is told it took the value only when the protocol ran to the end AND its own claim was "
    "still in the store. A refusal covers the key not being there, another caller having taken it, and "
    "a claim that expired mid-protocol - the last on a single caller with nobody to lose to, its "
    "outcome being the value gone with nobody able to be told they took it. A store fault after the "
    f"removal raises rather than returning, so it never reaches the refusal. Contract: {DECLARING}."
)


def tracked_sources() -> list[str]:
    listed = subprocess.run(
        ["git", "ls-files", "src/*.cs"], capture_output=True, text=True, check=True)
    return [line for line in listed.stdout.splitlines() if line]


def main() -> int:
    found = {
        path for path in tracked_sources()
        if path != DECLARING and CALL.search(pathlib.Path(path).read_text(encoding="utf-8-sig"))
    }

    added = sorted(found - KNOWN)
    gone = sorted(KNOWN - found)

    if not added and not gone:
        return 0

    for path in added:
        print(f"{path}: consumes the take-once protocol and is not in the reviewed list.")

    for path in gone:
        print(f"{path}: no longer consumes the take-once protocol, but is still in the list.")

    print(f"\n{CONTRACT}")
    print(
        f"\nDescribe the refusal from that contract rather than from the shape of the call, then update "
        f"KNOWN in {pathlib.Path(__file__).name}.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
