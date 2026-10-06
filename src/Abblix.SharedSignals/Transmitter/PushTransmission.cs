// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Telemetry;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// How one push transmission ended.
/// </summary>
/// <param name="Continues">Whether the pass may go on to the next item; false keeps this item at the head of the
/// queue.</param>
/// <param name="Outcome">How the receiver answered, one of <see cref="PushDeliveryOutcomes"/>.</param>
/// <param name="TransportFailure">The failure that kept the receiver from answering, if one did.</param>
internal readonly record struct PushTransmission(bool Continues, string Outcome, Exception? TransportFailure = null)
{
    /// <summary>
    /// The receiver accepted the token, and the pass goes on.
    /// </summary>
    public static PushTransmission Delivered => new(true, PushDeliveryOutcomes.Delivered);

    /// <summary>
    /// The receiver answered "400 Bad Request"; <paramref name="continues"/> tells whether its verdict let the event go.
    /// </summary>
    public static PushTransmission Refused(bool continues) => new(continues, PushDeliveryOutcomes.Refused);

    /// <summary>
    /// The receiver gave no usable answer, and the pass stops with the token at the head of the queue.
    /// </summary>
    public static PushTransmission Failed(Exception? transportFailure = null)
        => new(false, PushDeliveryOutcomes.Failed, transportFailure);
}
