// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
    }
}
