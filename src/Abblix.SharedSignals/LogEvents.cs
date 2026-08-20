// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
    }
}
