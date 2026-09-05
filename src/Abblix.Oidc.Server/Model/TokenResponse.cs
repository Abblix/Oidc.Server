// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// The response from an OAuth 2.0 / OpenID Connect token endpoint. This is the framework-neutral wire DTO both
/// transport adapters (MVC, Minimal API) serialize; serialization is identical across frameworks, so a single core
/// type serves both.
/// </summary>
public record TokenResponse
{
    private static class Parameters
    {
        public const string AccessToken = "access_token";
        public const string TokenType = "token_type";
        public const string IssuedTokenType = "issued_token_type";
        public const string ExpiresIn = "expires_in";
        public const string RefreshToken = "refresh_token";
        public const string Scope = "scope";
        public const string IdToken = "id_token";
        public const string AuthorizationDetails = "authorization_details";
    }

    /// <summary>
    /// The access token issued by the authorization server.
    /// REQUIRED by RFC 6749 section 5.1, so it is required here: a successful token response without it is
    /// not a response this server is allowed to send, and the compiler can say so where the null could not.
    /// </summary>
    [JsonPropertyName(Parameters.AccessToken)]
    [JsonPropertyOrder(1)]
    public required string AccessToken { get; init; }

    /// <summary>The type of the issued token, typically an absolute URI identifying the token type.</summary>
    [JsonPropertyName(Parameters.IssuedTokenType)]
    [JsonPropertyOrder(2)]
    public Uri? IssuedTokenType { get; set; }

    /// <summary>
    /// The type of token that is issued, usually 'Bearer'.
    /// REQUIRED by RFC 6749 section 5.1.
    /// </summary>
    [JsonPropertyName(Parameters.TokenType)]
    [JsonPropertyOrder(3)]
    public required string TokenType { get; init; }

    /// <summary>The lifetime in seconds of the access token.</summary>
    [JsonPropertyName(Parameters.ExpiresIn)]
    [JsonPropertyOrder(4)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    public TimeSpan ExpiresIn { get; init; }

    /// <summary>The refresh token, used to obtain new access tokens using the same authorization grant.</summary>
    [JsonPropertyName(Parameters.RefreshToken)]
    [JsonPropertyOrder(5)]
    public string? RefreshToken { get; init; }

    /// <summary>The scope of the access token as granted by the resource owner.</summary>
    [JsonPropertyName(Parameters.Scope)]
    [JsonPropertyOrder(6)]
    [JsonConverter(typeof(SpaceSeparatedValuesConverter))]
    public string[]? Scope { get; init; }

    /// <summary>The ID token (a JWT carrying the user's identity), present in OpenID Connect flows.</summary>
    [JsonPropertyName(Parameters.IdToken)]
    [JsonPropertyOrder(7)]
    public string? IdToken { get; init; }

    /// <summary>
    /// RFC 9396 §7 <c>authorization_details</c>: the structured authorization data the token was granted for, echoed
    /// back to the client byte-exact. Omitted when no Rich Authorization Request was used.
    /// </summary>
    [JsonPropertyName(Parameters.AuthorizationDetails)]
    [JsonPropertyOrder(8)]
    public JsonArray? AuthorizationDetails { get; init; }
}
