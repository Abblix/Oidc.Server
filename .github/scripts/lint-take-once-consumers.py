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

#: Three ways in. The two extension methods by name; the flag that routes a read through the same
#: protocol one layer up - `IEntityStorage.GetAsync(..., removeOnRetrieval: true)` and
#: `IAuthorizationRequestStorage.TryGetAsync(..., shouldRemove: true)`; and the DECLARATION of that
#: flag, because the file declaring it is the one carrying the contract prose and it never passes the
#: argument to itself. A name grep alone was blind to the second route, and both call-shaped routes
#: were blind to the third - which is where the sentences this checker exists over actually live.
CALL = re.compile(
    r"\b(TryRemoveAsync|TryGetAndRemoveAsync)\b"
    r"|\b(removeOnRetrieval|shouldRemove)\s*:\s*true\b"
    r"|\bbool\s+(removeOnRetrieval|shouldRemove)\b")

DECLARING = "src/Abblix.Utils/DistributedCacheExtensions.cs"

#: Every file in `src/` that reaches the take-once protocol, by either route, as of the sweep for issue
#: 455. Each was checked against the contract rather than against the call's shape, and adding a name
#: here is the moment to read that contract.
#:
#: This is what the checker CAN see - the reach of the three routes above, rather than a proof that
#: nothing else redeems. What it cannot see is in WRAPPERS below.
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
    "src/Abblix.Oidc.Server/Features/Storages/AuthorizationRequestStorage.cs",
    "src/Abblix.Oidc.Server/Features/Storages/IAuthorizationRequestStorage.cs",
    "src/Abblix.Oidc.Server/Features/Storages/IEntityStorage.cs",
}

#: A caller reaching the protocol through a WRAPPER that renames it names none of the three routes, so
#: no pattern here finds it and no pattern here notices when it stops being one. These are recorded by
#: hand, are not measured, and are listed so that the checker's blind spot is a NAMED file rather than a
#: hypothetical: `IAuthorizationCodeService` declares `RemoveAuthorizationCodeAsync` over an
#: implementation that IS measured, and describes this refusal in its own `<returns>`.
WRAPPERS = {
    "src/Abblix.Oidc.Server/Features/Storages/IAuthorizationCodeService.cs",
}

CONTRACT = (
    "A caller is told it took the value only when the protocol ran to the end AND its own claim was "
    "still in the store. A refusal covers the key not being there, another caller having taken it, and "
    "a claim that expired mid-protocol - the last on a single caller with nobody to lose to, its "
    "outcome being the value gone with nobody able to be told they took it. A store fault after the "
    f"removal raises rather than returning, so it never reaches the refusal. Contract: {DECLARING}."
)


def tracked_sources() -> list[str]:
    # Two separate defaults are relative to the CURRENT directory here, and each has to be overridden by
    # its own flag. `:(top)` anchors the PATTERN, without which the same command run from `src/` matches
    # nothing and this checker answers a clean zero over a sweep that read no files. `--full-name`
    # anchors the OUTPUT, without which the paths come back relative to the caller and neither KNOWN nor
    # the read below can be written against them. Anchoring one and not the other still moves the reach.
    listed = subprocess.run(
        ["git", "ls-files", "--full-name", ":(top)src/*.cs"],
        capture_output=True, text=True, check=True)
    return [line for line in listed.stdout.splitlines() if line]


def repository_root() -> pathlib.Path:
    # The paths `tracked_sources` yields are repo-relative, so they are only readable from here - the
    # command works from any directory and its answer does not.
    located = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True)
    return pathlib.Path(located.stdout.strip())


def main() -> int:
    root = repository_root()
    sources = tracked_sources()

    # A silence has to mean something was read. Nothing to read is a broken invocation, never an
    # all-clear, and the two are the same output until this refuses one of them.
    if not sources:
        print("no tracked .cs files under src/; nothing was checked.")
        return 2

    found = {
        path for path in sources
        if path != DECLARING and CALL.search((root / path).read_text(encoding="utf-8-sig"))
    }

    added = sorted(found - KNOWN)
    gone = sorted(KNOWN - found)

    if not added and not gone:
        print(f"{len(sources)} tracked source(s) read; {len(KNOWN)} known consumer(s), unchanged.")
        return 0

    for path in added:
        print(f"{path}: consumes the take-once protocol and is not in the reviewed list.")

    for path in gone:
        print(f"{path}: no longer consumes the take-once protocol, but is still in the list.")

    print(f"\n{CONTRACT}")
    print(
        f"\nDescribe the refusal from that contract rather than from the shape of the call, then update "
        f"KNOWN in {pathlib.Path(__file__).name}.")
    print(
        "\nOutside what this checker measures, and carrying the same contract by hand: "
        + ", ".join(sorted(WRAPPERS)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
