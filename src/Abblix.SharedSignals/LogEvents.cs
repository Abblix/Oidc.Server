// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals;

/// <summary>
/// The identifiers this package's log entries carry, grouped by the area that emits them.
/// </summary>
/// <remarks>
/// The numbers are what a runbook keys on, so a range is allocated once and an identifier keeps
/// its value across every edit of the message it names. This XML doc is the allocation record.
/// </remarks>
public static class LogEvents
{
    /// <summary>
    /// The transmitter role: 2000-2099.
    /// </summary>
    public static class Transmitter
    {
        private const int Base = 2000;

        /// <summary>A delivery sweep failed as a whole, and will be attempted again.</summary>
        public const int PushSweepFailed = Base + 1;

        /// <summary>One stream's delivery failed; the sweep carried on with the rest.</summary>
        public const int PushStreamFailed = Base + 2;

        /// <summary>An event could not be queued for one stream; the fan-out reached the others.</summary>
        public const int StreamNotReached = Base + 3;

        /// <summary>This instance began sweeping push streams, and by what it claims them.</summary>
        public const int PushSweepingStarted = Base + 4;

        /// <summary>Another instance holds this stream's delivery claim, so this one passed it by.</summary>
        public const int PushStreamClaimedElsewhere = Base + 5;

        /// <summary>A delivery pass outlived its claim and was cut off at the deadline.</summary>
        public const int PushPassCutOff = Base + 6;

        /// <summary>The receiver refused SETs on one pass, and said why.</summary>
        public const int SetsRefusedByReceiver = Base + 7;

        /// <summary>The receiver objected to this transmitter rather than to the SET, so the queue is held.</summary>
        public const int ReceiverObjected = Base + 8;

        /// <summary>The configuration document publishes no jwks_uri, so no receiver can verify an event.</summary>
        public const int NoJwksUriAdvertised = Base + 9;

        /// <summary>The advertised authorization schemes omit OAuth 2.0, which the CAEP profile requires.</summary>
        public const int OAuthSchemeNotAdvertised = Base + 10;

        /// <summary>No scope is checked on the management API, which the CAEP profile requires.</summary>
        public const int ScopeCheckingDisabled = Base + 11;

        /// <summary>A new stream covers no subject, while a conformant receiver adds none.</summary>
        public const int NoSubjectsIncludedByDefault = Base + 12;
    }
}
