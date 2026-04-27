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

using System.Globalization;
using System.Text.Json.Serialization;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.DeclarativeValidation;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// The set of parameters carried by an OAuth 2.0 / OpenID Connect authorization request to the
/// <c>authorization_endpoint</c> as defined in RFC 6749 §4.1.1 and OpenID Connect Core 1.0 §3.1.2.1.
/// Parameters are bound from query string, form body, or a Request Object passed via
/// <see cref="Request"/> / <see cref="RequestUri"/> (OIDC Core §6).
/// </summary>
public record AuthorizationRequest
{
	/// <summary>
	/// The requested scopes, which specify the access privileges requested as part of the authorization.
	/// Common scopes include 'openid', 'profile', 'email', 'phone', 'address', and 'offline_access'.
	/// </summary>
	[JsonPropertyName(Parameters.Scope)]
	[JsonConverter(typeof(SpaceSeparatedValuesConverter))]
	public string[] Scope { get; init; } = [];

	/// <summary>
	/// The detailed request for specific claims (user attributes) to be included in the ID token or
	/// returned from the UserInfo endpoint.
	/// </summary>
	[JsonPropertyName(Parameters.Claims)]
    public RequestedClaims? Claims { get; init; }

	/// <summary>
	/// The OAuth 2.0 <c>response_type</c> parameter (RFC 6749 §3.1.1, OIDC Core §3) that selects the grant flow:
	/// <c>code</c> for authorization code, <c>token</c> for the implicit grant access token, <c>id_token</c> for the
	/// hybrid/implicit ID token. Multiple values are space-separated and represented here as an array.
	/// </summary>
	[JsonPropertyName(Parameters.ResponseType)]
	[JsonConverter(typeof(SpaceSeparatedValuesConverter))]
    [AllowedValues(ResponseTypes.Code, ResponseTypes.Token, ResponseTypes.IdToken)]
    public string[]? ResponseType { get; init; }

	/// <summary>
	/// The OAuth 2.0 <c>client_id</c> identifying the relying party that issued the request,
	/// per RFC 6749 §4.1.1. Required for any conformant authorization request.
	/// </summary>
	[JsonPropertyName(Parameters.ClientId)]
	public string? ClientId { get; init; }

	/// <summary>
	/// The OAuth 2.0 <c>redirect_uri</c> (RFC 6749 §3.1.2) where the authorization response is delivered.
	/// Must be an absolute URI and must exactly match one of the redirect URIs pre-registered for the client.
	/// </summary>
	[JsonPropertyName(Parameters.RedirectUri)]
    [AbsoluteUri]
    public Uri? RedirectUri { get; init; }

	/// <summary>
	/// The opaque <c>state</c> value (RFC 6749 §4.1.1) returned unchanged in the authorization response
	/// so the client can correlate request and response and protect against cross-site request forgery.
	/// </summary>
	[JsonPropertyName(Parameters.State)]
    public string? State { get; init; }

	/// <summary>
	/// The OAuth 2.0 <c>response_mode</c> parameter (OAuth 2.0 Multiple Response Types / OAuth 2.0 Form Post Response Mode)
	/// selecting how the authorization response is delivered: <c>query</c>, <c>fragment</c>, or <c>form_post</c>.
	/// </summary>
	[JsonPropertyName(Parameters.ResponseMode)]
    [AllowedValues(ResponseModes.FormPost, ResponseModes.Fragment, ResponseModes.Query)]
    public string? ResponseMode { get; init; }

	/// <summary>
	/// The OIDC <c>nonce</c> (OIDC Core §3.1.2.1) bound into the issued ID Token to prevent token replay.
	/// Required for the implicit and hybrid flows; recommended for the authorization code flow.
	/// </summary>
	[JsonPropertyName(Parameters.Nonce)]
    public string? Nonce { get; init; }

	/// <summary>
	/// The OIDC <c>display</c> parameter (OIDC Core §3.1.2.1) hinting how the authentication and consent UI
	/// should be rendered: <c>page</c>, <c>popup</c>, <c>touch</c>, or <c>wap</c>.
	/// </summary>
	[JsonPropertyName(Parameters.Display)]
    [AllowedValues(DisplayModes.Page, DisplayModes.Popup, DisplayModes.Touch, DisplayModes.Wap)]
    public string? Display { get; init; }

	/// <summary>
	/// The OIDC <c>prompt</c> parameter (OIDC Core §3.1.2.1) controlling whether the authorization server
	/// re-prompts for authentication and consent. Values: <c>none</c>, <c>login</c>, <c>consent</c>,
	/// <c>select_account</c>, and the registration extension <c>create</c>.
	/// </summary>
	[JsonPropertyName(Parameters.Prompt)]
    [AllowedValues(Prompts.Create, Prompts.Consent, Prompts.Login, Prompts.None, Prompts.SelectAccount)]
    public string? Prompt { get; init; }

	/// <summary>
	/// The OIDC <c>max_age</c> parameter (OIDC Core §3.1.2.1) bounding the elapsed time since the last
	/// active end-user authentication. Serialized as an integer number of seconds.
	/// </summary>
	[JsonPropertyName(Parameters.MaxAge)]
	[JsonConverter(typeof(TimeSpanSecondsConverter))]
    public TimeSpan? MaxAge { get; init; }

	/// <summary>
	/// The OIDC <c>ui_locales</c> parameter (OIDC Core §3.1.2.1), a preference-ordered list of BCP 47 language tags
	/// that the client wishes the authorization UI to be rendered in.
	/// </summary>
	[JsonPropertyName(Parameters.UiLocales)]
	[JsonConverter(typeof(ArrayConverter<CultureInfo, CultureInfoConverter>))]
    public CultureInfo[]? UiLocales { get; init; }

	/// <summary>
	/// The OIDC <c>claims_locales</c> parameter (OIDC Core §5.2), preference-ordered BCP 47 language tags
	/// the client prefers when claims are returned in localized form.
	/// </summary>
	[JsonPropertyName(Parameters.ClaimsLocales)]
	[JsonConverter(typeof(ArrayConverter<CultureInfo, CultureInfoConverter>))]
    public CultureInfo[]? ClaimsLocales { get; init; }

	/// <summary>
	/// The OIDC <c>id_token_hint</c> (OIDC Core §3.1.2.1), a previously issued ID Token used as a hint about
	/// the end-user's current or past authenticated session, typically combined with <c>prompt=none</c>.
	/// </summary>
	[JsonPropertyName(Parameters.IdTokenHint)]
    public string? IdTokenHint { get; init; }

	/// <summary>
	/// The OIDC <c>login_hint</c> (OIDC Core §3.1.2.1) suggesting the login identifier (such as an email or phone)
	/// that the authorization server should use to pre-fill the authentication UI.
	/// </summary>
	[JsonPropertyName(Parameters.LoginHint)]
    public string? LoginHint { get; init; }

	/// <summary>
	/// The OIDC <c>acr_values</c> (OIDC Core §3.1.2.1), a preference-ordered list of Authentication Context Class
	/// Reference values that the client requests the authorization server to satisfy during authentication.
	/// </summary>
	[JsonPropertyName(Parameters.AcrValues)]
	[JsonConverter(typeof(SpaceSeparatedValuesConverter))]
    public string[]? AcrValues { get; init; }

	/// <summary>
	/// The PKCE <c>code_challenge</c> (RFC 7636 §4.3), a high-entropy value derived from the client-held
	/// <c>code_verifier</c> using <see cref="CodeChallengeMethod"/>. Required for public clients to defend
	/// the authorization code against interception.
	/// </summary>
	[JsonPropertyName(Parameters.CodeChallenge)]
    public string? CodeChallenge { get; init; }

	/// <summary>
	/// The PKCE <c>code_challenge_method</c> (RFC 7636 §4.3) declaring how <see cref="CodeChallenge"/> was
	/// derived from the code verifier. <c>S256</c> is required by current best-practice profiles; <c>plain</c>
	/// is supported only for legacy compatibility.
	/// </summary>
	[JsonPropertyName(Parameters.CodeChallengeMethod)]
    [AllowedValues(CodeChallengeMethods.Plain, CodeChallengeMethods.S256, CodeChallengeMethods.S512)]
    public string? CodeChallengeMethod { get; init; }

	/// <summary>
	/// A JWT (JSON Web Token) that encapsulates the entire authorization request as its payload.
	/// This parameter is often used to transmit the request securely.
	/// </summary>
	[JsonPropertyName(Parameters.Request)]
	public string? Request { get; init; }

	/// <summary>
	/// A URL referencing a resource that contains a Request Object, which is a JWT with the authorization request
	/// parameters as its claims. This URL must use HTTPS.
	/// </summary>
	[JsonPropertyName(Parameters.RequestUri)]
	[AbsoluteUri(RequireScheme = "https")]
	public Uri? RequestUri { get; init; }

	/// <summary>
	/// Specifies the resource for which the access token is requested.
	/// As defined in RFC 8707, this parameter is used to request access tokens with a specific scope for a particular
	/// resource.
	/// </summary>
	[JsonPropertyName(Parameters.Resource)]
	[JsonConverter(typeof(SingleOrArrayConverter<Uri>))]
	public Uri[]? Resources { get; set; }

	public static class Parameters
    {
        public const string Scope = "scope";
        public const string Claims = "claims";
        public const string ResponseType = "response_type";
        public const string ClientId = "client_id";
        public const string RedirectUri = "redirect_uri";
        public const string State = "state";
        public const string ResponseMode = "response_mode";
        public const string Nonce = "nonce";
        public const string Display = "display";
        public const string Prompt = "prompt";
        public const string MaxAge = "max_age";
        public const string UiLocales = "ui_locales";
        public const string ClaimsLocales = "claims_locales";
        public const string IdTokenHint = "id_token_hint";
        public const string LoginHint = "login_hint";
        public const string AcrValues = "acr_values";
        public const string CodeChallenge = "code_challenge";
        public const string CodeChallengeMethod = "code_challenge_method";
        public const string Resource = "resource";

        public const string Request = "request";
        public const string RequestUri = "request_uri";
    }
}
