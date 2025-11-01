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
/// Represents an authorization request model containing the necessary properties
/// for an OpenID Connect or OAuth 2.0 authorization request.
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
	/// The requested response types.
	/// </summary>
	[JsonPropertyName(Parameters.ResponseType)]
	[JsonConverter(typeof(SpaceSeparatedValuesConverter))]
    [AllowedValues(ResponseTypes.Code, ResponseTypes.Token, ResponseTypes.IdToken)]
    public string[]? ResponseType { get; init; }

	/// <summary>
	/// The client ID of the requesting client.
	/// </summary>
	[JsonPropertyName(Parameters.ClientId)]
	public string? ClientId { get; init; }

	/// <summary>
	/// The redirect URI where the response should be sent.
	/// </summary>
	[JsonPropertyName(Parameters.RedirectUri)]
    [AbsoluteUri]
    public Uri? RedirectUri { get; init; }

	/// <summary>
	/// The optional state parameter to maintain state between the request and the callback.
	/// </summary>
	[JsonPropertyName(Parameters.State)]
    public string? State { get; init; }

	/// <summary>
	/// The requested response mode.
	/// </summary>
	[JsonPropertyName(Parameters.ResponseMode)]
    [AllowedValues(ResponseModes.FormPost, ResponseModes.Fragment, ResponseModes.Query)]
    public string? ResponseMode { get; init; }

	/// <summary>
	/// The nonce value used to associate the client session with an ID token.
	/// </summary>
	[JsonPropertyName(Parameters.Nonce)]
    public string? Nonce { get; init; }

	/// <summary>
	/// Specifies how the authorization server displays the authentication and consent UI.
	/// </summary>
	[JsonPropertyName(Parameters.Display)]
    [AllowedValues(DisplayModes.Page, DisplayModes.Popup, DisplayModes.Touch, DisplayModes.Wap)]
    public string? Display { get; init; }

	/// <summary>
	/// The prompt parameter, which specifies whether the authorization server prompts the user for
	/// re-authentication and consent.
	/// </summary>
	[JsonPropertyName(Parameters.Prompt)]
    [AllowedValues(Prompts.Create, Prompts.Consent, Prompts.Login, Prompts.None, Prompts.SelectAccount)]
    public string? Prompt { get; init; }

	/// <summary>
	/// Specifies the allowable elapsed time since the last user authentication.
	/// </summary>
	[JsonPropertyName(Parameters.MaxAge)]
	[JsonConverter(typeof(TimeSpanSecondsConverter))]
    public TimeSpan? MaxAge { get; init; }

	/// <summary>
	/// The UI locales requested for the user interface.
	/// </summary>
	[JsonPropertyName(Parameters.UiLocales)]
	[JsonConverter(typeof(ArrayConverter<CultureInfo, CultureInfoConverter>))]
    public CultureInfo[]? UiLocales { get; init; }

	/// <summary>
	/// The claims locales requested for the authorization response.
	/// </summary>
	[JsonPropertyName(Parameters.ClaimsLocales)]
	[JsonConverter(typeof(ArrayConverter<CultureInfo, CultureInfoConverter>))]
    public CultureInfo[]? ClaimsLocales { get; init; }

	/// <summary>
	/// The ID token hint, which can be used to pre-fill the authentication and consent UI.
	/// </summary>
	[JsonPropertyName(Parameters.IdTokenHint)]
    public string? IdTokenHint { get; init; }

	/// <summary>
	/// The login hint, which can be used to pre-fill the authentication UI.
	/// </summary>
	[JsonPropertyName(Parameters.LoginHint)]
    public string? LoginHint { get; init; }

	/// <summary>
	/// The Authentication Context Class References requested.
	/// </summary>
	[JsonPropertyName(Parameters.AcrValues)]
	[JsonConverter(typeof(SpaceSeparatedValuesConverter))]
    public string[]? AcrValues { get; init; }

	/// <summary>
	/// The code challenge, which is used in the PKCE extension for public clients.
	/// </summary>
	[JsonPropertyName(Parameters.CodeChallenge)]
    public string? CodeChallenge { get; init; }

	/// <summary>
	/// The code challenge method, which specifies the method used to derive the code challenge from the code
	/// verifier.
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
