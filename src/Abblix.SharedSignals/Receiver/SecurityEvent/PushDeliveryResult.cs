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

using System.Net;
using Abblix.SecurityEvents.Delivery;

namespace Abblix.SharedSignals.Receiver.SecurityEvent;

/// <summary>
/// What a push delivery request earns: the status code the transport answers with, and - only
/// beside a 400 - the error body the transmitter reads (RFC 8935 Sections 2.2, 2.3). The shape
/// is transport-neutral on purpose: any host adapter renders it, none decides it.
/// </summary>
/// <param name="StatusCode">The HTTP status the response carries.</param>
/// <param name="Error">The error body of a failure response; null on acceptance, whose response
/// body is empty (RFC 8935 Section 2.2).</param>
public sealed record PushDeliveryResult(HttpStatusCode StatusCode, DeliveryError? Error)
{
    /// <summary>
    /// The one success: "202 Accepted" with an empty body (RFC 8935 Section 2.2). A single
    /// shared instance, because acceptance carries no request-specific state.
    /// </summary>
    public static PushDeliveryResult Accepted { get; } = new(HttpStatusCode.Accepted, null);

    /// <summary>
    /// A rejection: "400 Bad Request" carrying the error the transmitter acts on
    /// (RFC 8935 Section 2.3).
    /// </summary>
    /// <param name="error">What was wrong with the SET, in registry vocabulary.</param>
    public static PushDeliveryResult BadRequest(DeliveryError error) => new(HttpStatusCode.BadRequest, error);
}
