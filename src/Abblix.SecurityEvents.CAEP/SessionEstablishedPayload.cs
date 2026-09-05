// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SecurityEvents.CAEP;

/// <summary>
/// Session Established (CAEP 1.0 Section 3.6): the transmitter established a new session for
/// the subject - how a service closes the loop with the identity provider after federation, how
/// an identity provider detects unintended logins, how a receiver inventories sessions. The
/// <see cref="CaepEventPayload.EventTimestamp"/> is the moment the session was established.
/// </summary>
public sealed record SessionEstablishedPayload : CaepEventPayload
{
    /// <summary>
    /// OPTIONAL. The user agent fingerprint the transmitter computed - qualities of the
    /// session, not its identity (CAEP 1.0 Section 3.6.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.FpUa)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FingerprintUserAgent { get; init; }

    /// <summary>
    /// OPTIONAL. The session's authentication context class reference, read as the same field
    /// of an OpenID Connect ID token (CAEP 1.0 Section 3.6.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.Acr)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AuthenticationContextClassReference { get; init; }

    /// <summary>
    /// OPTIONAL. The session's authentication methods references, each read as the same field
    /// of an OpenID Connect ID token (CAEP 1.0 Section 3.6.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.Amr)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? AuthenticationMethodsReferences { get; init; }

    /// <summary>
    /// OPTIONAL. The external session identifier correlating this session with a broader one,
    /// such as a federated SAML session (CAEP 1.0 Section 3.6.1).
    /// </summary>
    [JsonPropertyName(CaepClaimNames.ExtId)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ExternalId { get; init; }
}
