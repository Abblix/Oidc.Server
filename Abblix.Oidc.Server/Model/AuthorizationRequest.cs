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
using System.Text.Json.Nodes;
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
    /// RFC 9396 Rich Authorization Requests stored as the raw wire <see cref="JsonArray"/> so member order and
    /// type-specific payload survive the request → grant → token round-trip without re-serialisation.
    /// </summary>
    [JsonPropertyName(Parameters.AuthorizationDetails)]
    public JsonArray? AuthorizationDetails { get; init; }

	/// <summary>
	/// The OAuth 2.0 <c>response_type</c> parameter (RFC 6749 §3.1.1, OIDC Core §3) that selects the grant flow:
	/// <c>code</c> for authorization code,
	/// <c>token</c> for the implicit grant access token,
	/// <c>id_token</c> for the hybrid/implicit ID token.
	/// Multiple values are space-separated and represented here as an array.
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

	/// <summary>
	/// Client's pre-commitment to a DPoP proof-of-possession key per RFC 9449 §10
	/// (<c>dpop_jkt</c> parameter): the base64url-encoded RFC 7638 JWK Thumbprint of the
	/// key the client will demonstrate at the token endpoint. Persisted with the
	/// authorization code so /token can reject mismatched proofs and close the
	/// authorization-code injection window.
	/// </summary>
	[JsonPropertyName(Parameters.DpopJkt)]
	public string? ProofKeyThumbprint { get; init; }

	/// <summary>
    /// Wire-level parameter names accepted at the authorization endpoint per RFC 6749 §4.1.1,
    /// OpenID Connect Core 1.0 §3.1.2.1, RFC 7636 (PKCE), RFC 8707 (resource indicators),
    /// and RFC 9449 §10 (DPoP).
    /// </summary>
    public static class Parameters
    {
        /// <summary>The <c>scope</c> authorization request parameter listing requested OAuth/OIDC scopes.
        /// </summary>
        public const string Scope = "scope";

        /// <summary>The <c>claims</c> authorization request parameter carrying a structured request for
        /// specific claims to appear in the ID Token or UserInfo response.</summary>
        public const string Claims = "claims";

        /// <summary>The <c>authorization_details</c> authorization request parameter (RFC 9396 §2)
        /// carrying a JSON array of structured authorization requirements per the RFC 9396 Rich
        /// Authorization Requests profile.</summary>
        public const string AuthorizationDetails = "authorization_details";

        /// <summary>The <c>response_type</c> authorization request parameter selecting the grant flow
        /// (e.g. <c>code</c>, <c>token</c>, <c>id_token</c> or combinations).</summary>
        public const string ResponseType = "response_type";

        /// <summary>The <c>client_id</c> authorization request parameter identifying the relying party.
        /// </summary>
        public const string ClientId = "client_id";

        /// <summary>The <c>redirect_uri</c> authorization request parameter naming the absolute URI to
        /// which the authorization response is delivered.</summary>
        public const string RedirectUri = "redirect_uri";

        /// <summary>The <c>state</c> authorization request parameter; an opaque value returned unchanged
        /// in the response for CSRF protection and correlation.</summary>
        public const string State = "state";

        /// <summary>The <c>response_mode</c> authorization request parameter selecting how the response
        /// is delivered to the redirect URI (<c>query</c>, <c>fragment</c>, <c>form_post</c>).</summary>
        public const string ResponseMode = "response_mode";

        /// <summary>The <c>nonce</c> authorization request parameter bound into the ID Token to prevent
        /// token replay.</summary>
        public const string Nonce = "nonce";

        /// <summary>The <c>display</c> authorization request parameter hinting how authentication and
        /// consent UI should be rendered.</summary>
        public const string Display = "display";

        /// <summary>The <c>prompt</c> authorization request parameter controlling re-prompting for
        /// authentication and consent.</summary>
        public const string Prompt = "prompt";

        /// <summary>The <c>max_age</c> authorization request parameter bounding the elapsed time since
        /// the last end-user authentication, in seconds.</summary>
        public const string MaxAge = "max_age";

        /// <summary>The <c>ui_locales</c> authorization request parameter listing preferred UI locales as
        /// BCP 47 tags.</summary>
        public const string UiLocales = "ui_locales";

        /// <summary>The <c>claims_locales</c> authorization request parameter listing preferred locales
        /// for localised claim values.</summary>
        public const string ClaimsLocales = "claims_locales";

        /// <summary>The <c>id_token_hint</c> authorization request parameter carrying a previously issued
        /// ID Token as a hint about the end-user.</summary>
        public const string IdTokenHint = "id_token_hint";

        /// <summary>The <c>login_hint</c> authorization request parameter suggesting the login identifier
        /// to pre-fill in the authentication UI.</summary>
        public const string LoginHint = "login_hint";

        /// <summary>The <c>acr_values</c> authorization request parameter listing requested Authentication
        /// Context Class Reference values.</summary>
        public const string AcrValues = "acr_values";

        /// <summary>The <c>code_challenge</c> PKCE parameter (RFC 7636 §4.3) derived from the client's
        /// code verifier.</summary>
        public const string CodeChallenge = "code_challenge";

        /// <summary>The <c>code_challenge_method</c> PKCE parameter declaring how the code challenge was
        /// derived (<c>S256</c>, <c>plain</c>).</summary>
        public const string CodeChallengeMethod = "code_challenge_method";

        /// <summary>The <c>resource</c> authorization request parameter (RFC 8707) targeting a specific
        /// protected resource for the issued access token.</summary>
        public const string Resource = "resource";

        /// <summary>The <c>request</c> authorization request parameter carrying a Request Object as a
        /// JWT (OpenID Connect Core §6.1).</summary>
        public const string Request = "request";

        /// <summary>The <c>request_uri</c> authorization request parameter referencing a Request Object
        /// hosted at an HTTPS URL (OpenID Connect Core §6.2).</summary>
        public const string RequestUri = "request_uri";

        /// <summary>The <c>dpop_jkt</c> authorization request parameter (RFC 9449 §10) carrying the
        /// base64url-encoded JWK Thumbprint of the DPoP key the client will demonstrate at the token
        /// endpoint.</summary>
        public const string DpopJkt = "dpop_jkt";
    }
}
