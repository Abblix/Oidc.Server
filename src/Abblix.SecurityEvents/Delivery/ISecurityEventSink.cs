// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Validation;

namespace Abblix.SecurityEvents.Delivery;

/// <summary>
/// Where validated events land: the application's half of a receiver, called once per accepted
/// SET with the token already carrying its issuer's authority.
/// </summary>
/// <remarks>
/// <para>
/// Processing must be idempotent: RFC 8935 Section 2 lets a transmitter deliver the same SET
/// again regardless of earlier responses, and the replay cache in front of this sink is
/// probabilistic, so a repeat can reach it. It must also tolerate events about subjects the
/// receiver has removed from the stream - a transmitter may keep sending them, and treating
/// that as an error would let anyone able to remove a subject break the receiver
/// (SSF 1.0 Section 9.3).
/// </para>
/// <para>
/// The verdict is the sink's to give: null acknowledges the event, a
/// <see cref="DeliveryError"/> travels back in the 400 response - the one the framework itself
/// defines being <see cref="DeliveryErrorCodes.InvalidState"/>, for a verification event whose
/// "state" does not match what this receiver sent (SSF 1.0 Section 8.1.4.1).
/// </para>
/// </remarks>
public interface ISecurityEventSink
{
    /// <summary>
    /// Consumes one validated SET.
    /// </summary>
    /// <param name="token">The validated token with its typed event payloads.</param>
    /// <param name="cancellationToken">Cancels the processing.</param>
    /// <returns>Null to acknowledge the event, or the error the delivery response carries.
    /// </returns>
    Task<DeliveryError?> ConsumeAsync(
        ValidatedSecurityEventToken token,
        CancellationToken cancellationToken = default);
}
