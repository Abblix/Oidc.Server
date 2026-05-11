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
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents the token delivery payload sent to the client in push mode.
/// </summary>
public sealed record BackChannelPushNotificationRequest : IBackChannelNotificationRequest
{
    /// <summary>
    /// The authentication request identifier.
    /// </summary>
    [JsonPropertyName(Parameters.AuthReqId)]
    public required string AuthenticationRequestId { get; init; }

    /// <summary>
    /// The access token issued by the authorization server.
    /// </summary>
    [JsonPropertyName(Parameters.AccessToken)]
    public required string AccessToken { get; init; }

    /// <summary>
    /// The type of the token (typically "Bearer").
    /// </summary>
    [JsonPropertyName(Parameters.TokenType)]
    public required string TokenType { get; init; }

    /// <summary>
    /// The lifetime in seconds of the access token.
    /// </summary>
    [JsonPropertyName(Parameters.ExpiresIn)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    public required TimeSpan ExpiresIn { get; init; }

    /// <summary>
    /// The ID token, if requested.
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
    /// (OpenID Connect CIBA Core 1.0 §10.3.1).
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

        /// <summary>The <c>id_token</c> push payload parameter carrying the issued ID Token, when one was
        /// requested.</summary>
        public const string IdToken = "id_token";

        /// <summary>The <c>refresh_token</c> push payload parameter carrying the issued refresh token,
        /// when one was issued.</summary>
        public const string RefreshToken = "refresh_token";
    }
}
