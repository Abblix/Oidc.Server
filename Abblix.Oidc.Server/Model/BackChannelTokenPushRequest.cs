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
    /// The type of the token issued (typically "Bearer").
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
    /// Contains JSON property names for CIBA push mode token delivery.
    /// </summary>
    public static class Parameters
    {
        /// <summary>
        /// The authentication request identifier.
        /// </summary>
        public const string AuthReqId = "auth_req_id";

        /// <summary>
        /// The access token.
        /// </summary>
        public const string AccessToken = "access_token";

        /// <summary>
        /// The token type.
        /// </summary>
        public const string TokenType = "token_type";

        /// <summary>
        /// The token expiration time in seconds.
        /// </summary>
        public const string ExpiresIn = "expires_in";

        /// <summary>
        /// The ID token.
        /// </summary>
        public const string IdToken = "id_token";

        /// <summary>
        /// The refresh token.
        /// </summary>
        public const string RefreshToken = "refresh_token";
    }
}
