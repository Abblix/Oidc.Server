// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
