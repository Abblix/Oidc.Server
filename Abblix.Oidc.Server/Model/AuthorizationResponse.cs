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
/// The authorization response delivered to the client's redirect URI (via query, fragment or form_post), carrying
/// either the success parameters (code/tokens) or the error, or — under JARM — the single packed <c>response</c> JWT.
/// This is the framework-neutral wire projection both transport adapters serialize. It is distinct from the domain
/// result <see cref="Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse"/> (the abstract
/// pipeline outcome): the formatter flattens that domain result onto this wire shape.
/// </summary>
public record AuthorizationResponse
{
    private static class Parameters
    {
        public const string State = "state";
        public const string Code = "code";
        public const string TokenType = "token_type";
        public const string AccessToken = "access_token";
        public const string ExpiresIn = "expires_in";
        public const string IdToken = "id_token";
        public const string Error = "error";
        public const string ErrorDescription = "error_description";
        public const string ErrorUri = "error_uri";
        public const string Scope = "scope";
        public const string SessionState = "session_state";
        public const string Issuer = "iss";
        public const string Response = "response";
    }

    /// <summary>The error code when the authorization request failed.</summary>
    [JsonPropertyName(Parameters.Error)]
    public string? Error { init; get; }

    /// <summary>A human-readable explanation of the error.</summary>
    [JsonPropertyName(Parameters.ErrorDescription)]
    public string? ErrorDescription { init; get; }

    /// <summary>A URI with more information about the error.</summary>
    [JsonPropertyName(Parameters.ErrorUri)]
    public Uri? ErrorUri { init; get; }

    /// <summary>The client's <c>state</c>, returned unaltered.</summary>
    [JsonPropertyName(Parameters.State)]
    public string? State { init; get; }

    /// <summary>The authorization code to exchange at the token endpoint.</summary>
    [JsonPropertyName(Parameters.Code)]
    public string? Code { get; set; }

    /// <summary>The token type (typically <c>Bearer</c>) when an access token is delivered.</summary>
    [JsonPropertyName(Parameters.TokenType)]
    public string? TokenType { get; init; }

    /// <summary>The access token issued from the authorization endpoint (implicit/hybrid).</summary>
    [JsonPropertyName(Parameters.AccessToken)]
    public string? AccessToken { get; set; }

    /// <summary>The access token lifetime in seconds.</summary>
    [JsonPropertyName(Parameters.ExpiresIn)]
    [JsonConverter(typeof(TimeSpanSecondsConverter))]
    public TimeSpan? ExpiresIn { get; set; }

    /// <summary>The ID token (OpenID Connect flows).</summary>
    [JsonPropertyName(Parameters.IdToken)]
    public string? IdToken { get; set; }

    /// <summary>The granted scope.</summary>
    [JsonPropertyName(Parameters.Scope)]
    public string? Scope { get; set; }

    /// <summary>The OpenID Connect Session Management session state.</summary>
    [JsonPropertyName(Parameters.SessionState)]
    public string? SessionState { get; set; }

    /// <summary>The issuer of the response (RFC 9207).</summary>
    [JsonPropertyName(Parameters.Issuer)]
    public string? Issuer { get; set; }

    /// <summary>The JARM response JWT — when set, it is the sole wire parameter (RFC 9101 / JARM).</summary>
    [JsonPropertyName(Parameters.Response)]
    public string? Response { get; set; }
}
