// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;

namespace Abblix.SharedSignals.Model.Delivery;

/// <summary>
/// Poll delivery (SSF 1.0 Section 6.1.2, profiling RFC 8936): the receiver pulls SETs from the
/// URL the transmitter supplied. The URL may be shared across receivers but must be unique per
/// stream for a given receiver.
/// </summary>
/// <param name="endpointUrl">
/// Where events are retrieved from - supplied by the transmitter, which is exactly why it may be
/// null: a RECEIVER proposing poll delivery in a create or update request has no URL to offer,
/// so its proposal is the bare method (SSF 1.0 Sections 6.1.2, 8.1.1.1), while a
/// transmitter-issued stream configuration always carries the URL.</param>
[method: JsonConstructor]
public sealed class PollDeliveryMethod(Uri? endpointUrl = null) : StreamDeliveryMethod(MethodUri)
{
    /// <summary>
    /// The delivery method URI registered for poll delivery: "urn:ietf:rfc:8936"
    /// (SSF 1.0 Section 6.1.2).
    /// </summary>
    public const string MethodUri = "urn:ietf:rfc:8936";

    /// <summary>
    /// The URL where events can be retrieved from. Transmitter-supplied: present in every
    /// transmitter-issued configuration (SSF 1.0 Section 8.1.1.1), absent from a receiver's own
    /// proposal of poll delivery - the direction the null represents.
    /// </summary>
    [JsonPropertyName(ParameterNames.EndpointUrl)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? EndpointUrl { get; } = endpointUrl;
}
