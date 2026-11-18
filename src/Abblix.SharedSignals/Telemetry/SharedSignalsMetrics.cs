// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Telemetry;

/// <summary>
/// The instruments of the transmitter's meter, <see cref="SharedSignalsTelemetry.SourceName"/>.
/// </summary>
public static class SharedSignalsMetrics
{
    /// <summary>
    /// Counts the security events minted for a stream and put into its outbox, by
    /// <see cref="SharedSignalsTags.EventType"/> and <see cref="SharedSignalsTags.Tenant"/>.
    /// </summary>
    public const string EventsTransmitted = "ssf.events.transmitted";

    /// <summary>
    /// Counts the security event tokens posted to receivers, by <see cref="SharedSignalsTags.PushOutcome"/> and
    /// <see cref="SharedSignalsTags.Tenant"/>.
    /// </summary>
    public const string PushDeliveries = "ssf.push.deliveries";

    /// <summary>
    /// The time, in seconds, one push transmission of a security event token takes, from posting it until its answer
    /// is acted on, by <see cref="SharedSignalsTags.PushOutcome"/> and <see cref="SharedSignalsTags.Tenant"/>.
    /// </summary>
    public const string PushDeliveryDuration = "ssf.push.delivery.duration";
}
