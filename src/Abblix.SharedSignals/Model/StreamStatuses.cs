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

namespace Abblix.SharedSignals.Model;

/// <summary>
/// The allowable stream status values (SSF 1.0 Section 8.1.2.1). A standalone registry rather
/// than a nest under <see cref="StreamStatus"/>, because the Stream Updated Event carries the
/// same values in its own payload.
/// </summary>
public static class StreamStatuses
{
    /// <summary>
    /// The transmitter must transmit events over the stream, according to its configured
    /// delivery method (SSF 1.0 Section 8.1.2.1).
    /// </summary>
    public const string Enabled = "enabled";

    /// <summary>
    /// The transmitter must not transmit and should hold what it would have sent, releasing it
    /// when the stream is enabled again - either in generation order, or only the latest events
    /// whose predecessors for the same subject principal they cancel or outdate
    /// (SSF 1.0 Section 8.1.2.1).
    /// </summary>
    public const string Paused = "paused";

    /// <summary>
    /// The transmitter must not transmit and holds nothing for later
    /// (SSF 1.0 Section 8.1.2.1).
    /// </summary>
    public const string Disabled = "disabled";
}
