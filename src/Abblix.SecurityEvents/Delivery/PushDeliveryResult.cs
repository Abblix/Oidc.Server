// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using Abblix.SecurityEvents.Delivery;

namespace Abblix.SecurityEvents.Delivery;

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

    /// <summary>
    /// The language of the error descriptions this package writes, for the header RFC 8935
    /// Section 2.3 requires beside them: "The response MUST include a 'Content-Language' header
    /// field whose value indicates the language of the error descriptions included in the response
    /// body."
    /// </summary>
    /// <remarks>
    /// Stated here rather than in each host adapter, because the language is a property of the
    /// descriptions and those are written here. A deployment translating them replaces the value
    /// where it replaces the text, and the two cannot then part.
    /// </remarks>
    public const string ErrorLanguage = "en";
}
