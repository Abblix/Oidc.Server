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
