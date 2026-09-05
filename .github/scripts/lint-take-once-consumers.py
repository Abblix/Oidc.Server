#!/usr/bin/env python3
"""Refuse a new consumer of the take-once protocol that nobody has read the contract for.

``DistributedCacheExtensions.TryRemoveAsync`` and ``TryGetAndRemoveAsync`` answer that a caller took the
value only when the protocol ran to the end AND its own claim was still in the store. Everything else is
a refusal, and only one of the ways there involves a competitor. A store call that fails after the removal
is an OUTCOME rather than a cause: it raises, and the caller is handed an exception instead of an answer.
The ``CONTRACT`` string below is the sentence this file exists to make somebody read; it is stated as the
condition rather than as a list, for the same reason the consumers are.

Every consumer that wrote its own ``<returns>`` from the shape of the call - rather than from that
contract - said "a concurrent request already claimed it", and an operator told a second request was the
cause goes looking for a second node while the single-caller case is exactly the one that never produces
one.

Prose cannot be checked here without crying wolf: "concurrent" is a legitimate word in most of these
files, and a detector with false positives trains everyone to wave it away. What CAN be checked exactly
is the REACH - who consumes the protocol at all. This list is the answer, and a change to it fails until
somebody re-reads the contract and updates it deliberately.

Usage: ``lint-take-once-consumers.py``; it walks the tracked ``.cs`` files under ``src/``, from anywhere
in the working tree. Tests are outside its reach, so a test repeating the competitor story is not caught.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

#: A WRAPPER renames the protocol, so a file reaching it through one names none of the routes below.
#: Naming the wrapper's own method here is what turns that from a hand-kept list into a measurement, and
#: it finds both ends at once - the interface declaring it and every caller invoking it. A new wrapper
#: adds its name here; that is the one manual step, and it is one line rather than a roll of files.
WRAPPED = ["RemoveAuthorizationCodeAsync", "TakeRequestAsync"]

#: Four ways in. The two extension methods by name; the flag that routes a read through the same protocol
#: one layer up - `IEntityStorage.GetAsync(..., removeOnRetrieval: true)` and
#: `IAuthorizationRequestStorage.TryGetAsync(..., shouldRemove: true)`; the DECLARATION of that flag,
#: because the file declaring it carries the contract prose and never passes the argument to itself; and
#: the wrapper names above. A name grep alone was blind to the flag, both call-shaped routes were blind to
#: the declaration - which is where the sentences this checker exists over live - and all three were blind
#: to the wrapper, including the decorator that mints the refusal string an operator greps.
CALL = re.compile(
    r"\b(TryRemoveAsync|TryGetAndRemoveAsync)\b"
    r"|\b(removeOnRetrieval|shouldRemove)\s*:\s*true\b"
    r"|\bbool\s+(removeOnRetrieval|shouldRemove)\b"
    r"|\b(" + "|".join(WRAPPED) + r")\b")

DECLARING = "src/Abblix.Utils/DistributedCacheExtensions.cs"

#: Every file in `src/` that reaches the take-once protocol, by either route, as of the sweep for issue
#: 455. Each was checked against the contract rather than against the call's shape, and adding a name
#: here is the moment to read that contract.
#:
#: This is the reach of the four routes above. It is not a proof that nothing else redeems: a route this
#: file does not name finds nothing, which is why WRAPPED is a list rather than a paragraph of prose.
KNOWN = {
    "src/Abblix.Oidc.Server/Endpoints/Token/Grants/BackChannelAuthenticationGrantHandler.cs",
    "src/Abblix.Oidc.Server/Endpoints/Token/Grants/DeviceCodeGrantHandler.cs",
    "src/Abblix.Oidc.Server/Features/BackChannelAuthentication/AuthenticationNotifiers/AuthenticationCompletionHandler.cs",
    "src/Abblix.Oidc.Server/Features/BackChannelAuthentication/AuthenticationNotifiers/PushModeCompletionHandler.cs",
    "src/Abblix.Oidc.Server/Features/BackChannelAuthentication/BackChannelRequestStorage.cs",
    "src/Abblix.Oidc.Server/Features/BackChannelAuthentication/GrantProcessors/PingModeGrantProcessor.cs",
    "src/Abblix.Oidc.Server/Features/BackChannelAuthentication/GrantProcessors/PollModeGrantProcessor.cs",
    "src/Abblix.Oidc.Server/Features/BackChannelAuthentication/Interfaces/IBackChannelRequestStorage.cs",
    "src/Abblix.Oidc.Server/Features/DeviceAuthorization/DeviceAuthorizationStorage.cs",
    "src/Abblix.Oidc.Server/Features/DeviceAuthorization/DeviceAuthorizationStorage.Logging.cs",
    "src/Abblix.Oidc.Server/Features/DeviceAuthorization/Interfaces/IDeviceAuthorizationStorage.cs",
    "src/Abblix.Oidc.Server/Features/Storages/DistributedCacheStorage.cs",
    "src/Abblix.Oidc.Server/Features/PushedAuthorization/PushedAuthorizationRequestProcessorDecorator.cs",
    "src/Abblix.Oidc.Server/Features/Storages/AuthorizationCodeService.cs",
    "src/Abblix.Oidc.Server/Features/Storages/AuthorizationRequestStorage.cs",
    "src/Abblix.Oidc.Server/Features/Storages/IAuthorizationRequestStorage.cs",
    "src/Abblix.Oidc.Server/Features/Storages/IAuthorizationCodeService.cs",
    "src/Abblix.Oidc.Server/Features/Storages/IEntityStorage.cs",
    "src/Abblix.Oidc.Server/Endpoints/Token/AuthorizationCodeReusePreventingDecorator.cs",
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
        "\nA file reaching the protocol through a wrapper is found only if that wrapper's method is in "
        f"WRAPPED, which currently names: {', '.join(WRAPPED)}.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
