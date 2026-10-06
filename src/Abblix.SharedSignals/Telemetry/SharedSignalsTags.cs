// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Telemetry;

/// <summary>
/// The attributes the transmitter puts on its spans and measurements, each from a set bounded by the deployment's own
/// configuration.
/// </summary>
public static class SharedSignalsTags
{
    /// <summary>
    /// The type of a security event: one the transmitter supports, since a stream is sent only the types it receives
    /// from that list, or one of the framework's own verification and stream-updated events.
    /// </summary>
    public const string EventType = "ssf.event_type";

    /// <summary>
    /// The identifier of the tenant the transmitter answers as, absent on a deployment answering as one issuer.
    /// </summary>
    public const string Tenant = "ssf.tenant";

    /// <summary>
    /// How a receiver answered a pushed security event token, one of <see cref="PushDeliveryOutcomes"/>.
    /// </summary>
    public const string PushOutcome = "ssf.push.outcome";

    /// <summary>
    /// The full name of the exception a span ended with; its message is never recorded, since a delivery failure's
    /// message names the stream and the receiver's address.
    /// </summary>
    public const string ErrorType = "error.type";
}
