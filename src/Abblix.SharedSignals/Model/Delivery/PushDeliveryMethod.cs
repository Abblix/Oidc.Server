// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SharedSignals.Model.Delivery;

/// <summary>
/// Push delivery (SSF 1.0 Section 6.1.1, profiling RFC 8935): the transmitter POSTs each SET to
/// the URL the receiver supplied at stream creation.
/// </summary>
/// <param name="endpointUrl">
/// Where events are pushed through HTTP POST; set by the receiver. A receiver keeping several
/// streams from one transmitter apart is recommended a unique URL per stream.</param>
[method: JsonConstructor]
public sealed class PushDeliveryMethod(Uri endpointUrl) : StreamDeliveryMethod(MethodUri)
{
    /// <summary>
    /// The delivery method URI registered for push delivery: "urn:ietf:rfc:8935"
    /// (SSF 1.0 Section 6.1.1).
    /// </summary>
    public const string MethodUri = "urn:ietf:rfc:8935";

    /// <summary>
    /// The wire names specific to push delivery.
    /// </summary>
    public new static class ParameterNames
    {
        /// <summary>
        /// The authorization header the transmitter must send with every push, when the
        /// receiver's endpoint requires one (SSF 1.0 Section 6.1.1).
        /// </summary>
        public const string AuthorizationHeader = "authorization_header";
    }

    /// <summary>
    /// The URL where events are pushed through HTTP POST; supplied by the receiver
    /// (SSF 1.0 Section 6.1.1).
    /// </summary>
    [JsonPropertyName(StreamDeliveryMethod.ParameterNames.EndpointUrl)]
    public Uri EndpointUrl { get; } = endpointUrl ?? throw new ArgumentNullException(nameof(endpointUrl));

    /// <summary>
    /// The value the transmitter must send in the Authorization header of every HTTP request to
    /// the endpoint, when the receiver provided one at stream creation or update
    /// (SSF 1.0 Section 6.1.1). Null when the endpoint needs no authorization.
    /// </summary>
    [JsonPropertyName(ParameterNames.AuthorizationHeader)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AuthorizationHeader { get; init; }
}
