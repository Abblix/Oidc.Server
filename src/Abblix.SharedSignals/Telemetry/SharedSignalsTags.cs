// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Telemetry;

/// <summary>
/// The attributes the transmitter puts on its spans and measurements.
/// </summary>
public static class SharedSignalsTags
{
    /// <summary>
    /// The type of a security event, as the host dispatched it. Dispatching to every matching stream sends only the
    /// types a stream receives; dispatching to one stream sends whatever type it is given, which the library itself uses
    /// only for its verification and stream-updated events.
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
