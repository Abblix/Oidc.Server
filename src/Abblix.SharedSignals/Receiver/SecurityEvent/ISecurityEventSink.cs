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

using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Validation;

namespace Abblix.SharedSignals.Receiver.SecurityEvent;

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
