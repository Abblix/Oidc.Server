// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Telemetry;

/// <summary>
/// How a receiver answered a pushed security event token, the values of <see cref="SharedSignalsTags.PushOutcome"/>.
/// </summary>
public static class PushDeliveryOutcomes
{
    /// <summary>
    /// The receiver accepted the token.
    /// </summary>
    public const string Delivered = "delivered";

    /// <summary>
    /// The receiver answered "400 Bad Request" (RFC 8935 Section 2.3), whether its verdict dropped the event or kept
    /// it queued for a transmitter that has to fix its credentials first.
    /// </summary>
    public const string Refused = "refused";

    /// <summary>
    /// The receiver gave no answer, answered with a status other than success and 400, or answered but the outbox
    /// could not record the answer; the event stays queued.
    /// </summary>
    public const string Failed = "failed";
}
