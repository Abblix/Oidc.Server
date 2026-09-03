// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents the token payload sent to the client in CIBA push mode.
/// Per CIBA specification, this payload is delivered to the client's registered notification endpoint.
/// </summary>
public record BackChannelTokenPushRequest
{
    /// <summary>
    /// The authentication request identifier that correlates this token delivery with the original request.
    /// </summary>
    [JsonPropertyName(Parameters.AuthReqId)]
    public required string AuthenticationRequestId { get; init; }

    /// <summary>
    /// The access token issued by the authorization server.
    /// </summary>
    [JsonPropertyName(Parameters.AccessToken)]
    public required string AccessToken { get; init; }

    /// <summary>
    /// The type of the token issued (typically <c>Bearer</c>).
    /// </summary>
    [JsonPropertyName(Parameters.TokenType)]
    public required string TokenType { get; init; }

    /// <summary>
    /// The lifetime of the access token.
    /// Serialized as seconds per OAuth 2.0 specification.
    /// </summary>
    [JsonPropertyName(Parameters.ExpiresIn)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    public required TimeSpan ExpiresIn { get; init; }

    /// <summary>
    /// The ID token containing authentication information and validation hashes.
    /// Required in push mode per CIBA specification.
    /// </summary>
    [JsonPropertyName(Parameters.IdToken)]
    public string? IdToken { get; init; }

    /// <summary>
    /// The refresh token, if issued.
    /// </summary>
    [JsonPropertyName(Parameters.RefreshToken)]
    public string? RefreshToken { get; init; }

    /// <summary>
    /// Wire-level parameter names for the CIBA push-mode token delivery payload
    /// (OpenID Connect CIBA Core 1.0 section 10.3.1).
    /// </summary>
    public static class Parameters
    {
        /// <summary>The <c>auth_req_id</c> push payload parameter identifying the original CIBA request.
        /// </summary>
        public const string AuthReqId = "auth_req_id";

        /// <summary>The <c>access_token</c> push payload parameter carrying the issued access token.
        /// </summary>
        public const string AccessToken = "access_token";

        /// <summary>The <c>token_type</c> push payload parameter naming the access token type
        /// (typically <c>Bearer</c>).</summary>
        public const string TokenType = "token_type";

        /// <summary>The <c>expires_in</c> push payload parameter giving the access token lifetime in
        /// seconds.</summary>
        public const string ExpiresIn = "expires_in";

        /// <summary>The <c>id_token</c> push payload parameter carrying the issued ID Token.</summary>
        public const string IdToken = "id_token";

        /// <summary>The <c>refresh_token</c> push payload parameter carrying the issued refresh token,
        /// when one was issued.</summary>
        public const string RefreshToken = "refresh_token";
    }
}
