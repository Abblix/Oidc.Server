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

namespace Abblix.Oidc.Client.Features.Tokens;

/// <summary>
/// What the token endpoint returns on success, per RFC 6749 section 5.1.
/// </summary>
/// <remarks>
/// Wire names are pinned with attributes rather than derived from a naming policy: the document comes from a
/// foreign provider, so reading it must not depend on how the host configures its serializer.
/// </remarks>
public sealed record TokenResponse
{
    /// <summary>
    /// The token presented to resource servers.
    /// </summary>
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; init; }

    /// <summary>
    /// How the access token is to be presented, almost always <c>Bearer</c>.
    /// </summary>
    [JsonPropertyName("token_type")]
    public required string TokenType { get; init; }

    /// <summary>
    /// Seconds until the access token expires, when the provider says.
    /// </summary>
    [JsonPropertyName("expires_in")]
    public int? ExpiresIn { get; init; }

    /// <summary>
    /// The token used to obtain a fresh set once the access token expires.
    /// </summary>
    /// <remarks>
    /// A provider that rotates refresh tokens returns a new one here on every refresh, and the one presented
    /// stops working the moment this arrives. Storing this value is therefore not an optimisation but a
    /// requirement: lose it and the session cannot be continued.
    /// </remarks>
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; init; }

    /// <summary>
    /// The token asserting who the user is. Present when the request carried the <c>openid</c> scope.
    /// </summary>
    [JsonPropertyName("id_token")]
    public string? IdToken { get; init; }

    /// <summary>
    /// What the issued access token is actually good for, when it differs from what was asked.
    /// </summary>
    [JsonPropertyName("scope")]
    public string? Scope { get; init; }

    /// <summary>
    /// Members of the response this client does not model, kept so a paid layer or a host can read a value
    /// the base client has no opinion about.
    /// </summary>
    [JsonExtensionData]
    public IDictionary<string, object?>? AdditionalData { get; init; }
}
