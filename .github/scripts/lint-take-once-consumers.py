#!/usr/bin/env python3
"""Refuse a new consumer of the take-once protocol that nobody has read the contract for.

``DistributedCacheExtensions.TryRemoveAsync`` and ``TryGetAndRemoveAsync`` refuse for three reasons and
only one of them involves a competitor: another caller took it, the claim EXPIRED mid-protocol, or a
store call after the removal failed. The last two need neither a second caller nor a second node.

Every consumer that wrote its own ``<returns>`` from the shape of the call - rather than from that
contract - said "a concurrent request already claimed it", and an operator told a second request was the
cause goes looking for a second node while the single-caller causes are exactly the ones that never
produce one. Seven sites said it before this check existed.

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

CALL = re.compile(r"\b(TryRemoveAsync|TryGetAndRemoveAsync)\b")

DECLARING = "src/Abblix.Utils/DistributedCacheExtensions.cs"

#: Every file in `src/` that consumes the take-once protocol, as of the sweep for issue 455. Each one
#: describes a refusal in its own words, and each was checked against the contract rather than against
#: the call's shape. Adding a name here is the moment to read that contract.
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
}

CONTRACT = (
    "A caller is told it took the value only when the protocol ran to the end AND its own claim was "
    "still in the store. A refusal covers the key not being there, another caller having taken it, a "
    "claim that expired mid-protocol, and the value being gone with nobody able to be told they took "
    "it - the last two on a single caller with no competitor at all. A store fault after the removal "
    f"raises rather than returning. The contract is on {DECLARING}."
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
        f"KNOWN in {pathlib.Path(__file__).as_posix().split('/')[-1]}.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
