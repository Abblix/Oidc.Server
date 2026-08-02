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

using System.Text.Json.Serialization;

namespace Abblix.SharedSignals.Model.Delivery;

/// <summary>
/// Poll delivery (SSF 1.0 Section 6.1.2, profiling RFC 8936): the receiver pulls SETs from the
/// URL the transmitter supplied. The URL may be shared across receivers but must be unique per
/// stream for a given receiver.
/// </summary>
/// <param name="endpointUrl">Where events are retrieved from; supplied by the transmitter.</param>
[method: JsonConstructor]
public sealed class PollDeliveryMethod(Uri endpointUrl) : StreamDeliveryMethod(MethodUri)
{
    /// <summary>
    /// The delivery method URI registered for poll delivery: "urn:ietf:rfc:8936"
    /// (SSF 1.0 Section 6.1.2).
    /// </summary>
    public const string MethodUri = "urn:ietf:rfc:8936";

    /// <summary>
    /// The URL where events can be retrieved from; supplied by the transmitter
    /// (SSF 1.0 Section 6.1.2).
    /// </summary>
    [JsonPropertyName(ParameterNames.EndpointUrl)]
    public Uri EndpointUrl { get; } = endpointUrl ?? throw new ArgumentNullException(nameof(endpointUrl));
}
