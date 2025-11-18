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

using System.ComponentModel.DataAnnotations;
using System.Globalization;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.DeclarativeValidation;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Binders;
using Microsoft.AspNetCore.Mvc;
using Core = Abblix.Oidc.Server.Model;
using Parameters = Abblix.Oidc.Server.Model.AuthorizationRequest.Parameters;

namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// Represents an authorization request model containing the necessary properties
/// for an OpenID Connect or OAuth 2.0 authorization process.
/// </summary>
public record AuthorizationRequest
{
	/// <summary>
	/// Identifies the permissions the application is requesting from the user.
	/// The specific scopes requested determine the access privileges granted.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.Scope)]
	[ModelBinder(typeof(SpaceSeparatedValuesBinder))]
	public string[] Scope { get; init; } = [];

	/// <summary>
	/// Specifies the information about the user that the application seeks to access,
	/// such as user profile data or email.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.Claims)]
	[ModelBinder(typeof(JsonSerializerModelBinder))]
    public RequestedClaims? Claims { get; init; }

	/// <summary>
	/// Indicates the type of response desired by the client, such as an authorization code
	/// or an identity token.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.ResponseType)]
    [AllowedValues(ResponseTypes.Code, ResponseTypes.Token, ResponseTypes.IdToken)]
	[ModelBinder(typeof(SpaceSeparatedValuesBinder))]
    public string[]? ResponseType { get; init; }

	/// <summary>
	/// Unique identifier of the client application making the authorization request.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.ClientId)]
	public string? ClientId { get; init; } = null!;

	/// <summary>
	/// URL to which the response from the authorization request should be sent.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.RedirectUri)]
    [AbsoluteUri]
    public Uri? RedirectUri { get; init; }

	/// <summary>
	/// A value used by the client to maintain state between the request and callback,
	/// helping to keep the external session and to prevent Cross-Site Request Forgery attacks.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.State)]
    public string? State { get; init; }

	/// <summary>
	/// Specifies the mechanism for returning parameters from the authorization endpoint,
	/// such as in the query string or fragment of the redirect URI.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.ResponseMode)]
    [AllowedValues(ResponseModes.FormPost, ResponseModes.Fragment, ResponseModes.Query)]
    public string? ResponseMode { get; init; }

	/// <summary>
	/// A string value used to associate a client session with an ID token.
	/// It is used to mitigate replay attacks.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.Nonce)]
    public string? Nonce { get; init; }

	/// <summary>
	/// Influences the user interface of the authorization server,
	/// suggesting how the authentication and consent UI should be displayed to the user.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.Display)]
    [AllowedValues(DisplayModes.Page, DisplayModes.Popup, DisplayModes.Touch, DisplayModes.Wap)]
    public string? Display { get; init; }

	/// <summary>
	/// Controls the behavior of the authorization server in terms of reauthentication and consent.
	/// It can instruct the server to prompt the user for reauthentication or consent.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.Prompt)]
    [AllowedValues(Prompts.Create, Prompts.Consent, Prompts.Login, Prompts.None, Prompts.SelectAccount)]
    public string? Prompt { get; init; }

	/// <summary>
	/// Specifies the maximum allowable elapsed time since the last user authentication,
	/// enabling clients to enforce reauthentication of users as needed.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.MaxAge)]
	[ModelBinder(typeof(SecondsToTimeSpanModelBinder))]
    public TimeSpan? MaxAge { get; init; }

	/// <summary>
	/// Represents the preferred locales for the user interface, allowing clients to request
	/// localization of the UI based on the user's preferences or language settings.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.UiLocales)]
	[ModelBinder(typeof(CultureInfoBinder))]
	public CultureInfo[]? UiLocales { get; init; }

	/// <summary>
	/// Represents the preferred locales for claims, allowing clients to request
	/// localization of claim values based on the user's preferences or language settings.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.ClaimsLocales)]
	[ModelBinder(typeof(CultureInfoBinder))]
	public CultureInfo[]? ClaimsLocales { get; init; }

	/// <summary>
	/// Can be used to pass an ID token hint to pre-fill or bypass the authentication
	/// and consent UI for a returning user.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.IdTokenHint)]
    public string? IdTokenHint { get; init; }

	/// <summary>
	/// Provides a hint to the authorization server about the login identifier the user might use.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.LoginHint)]
    public string? LoginHint { get; init; }

	/// <summary>
	/// Specifies the Authentication Context Class References,
	/// enabling clients to request certain levels of authentication assurance.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.AcrValues)]
	[ModelBinder(typeof(SpaceSeparatedValuesBinder))]
    public string[]? AcrValues { get; init; }

	/// <summary>
	/// Used in the PKCE (Proof Key for Code Exchange) extension for public clients,
	/// providing a challenge derived from the code verifier that will be sent in the token request.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.CodeChallenge)]
    public string? CodeChallenge { get; init; }

	/// <summary>
	/// Indicates the method used to derive the code challenge,
	/// supporting enhanced security for public clients in the PKCE flow.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.CodeChallengeMethod)]
    [AllowedValues(CodeChallengeMethods.Plain, CodeChallengeMethods.S256, CodeChallengeMethods.S512)]
    public string? CodeChallengeMethod { get; init; }

	/// <summary>
	/// Encapsulates the authorization request parameters in a JWT format,
	/// providing an additional layer of request integrity and confidentiality.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.Request)]
    public string? Request { get; init; }

	/// <summary>
	/// References a resource containing a Request Object value,
	/// allowing the use of external references for complex authorization requests.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.RequestUri)]
	[AbsoluteUri(RequireScheme = "https")]
	public Uri? RequestUri { get; init; }

	/// <summary>
	/// Specifies the resource for which the access token is requested.
	/// As defined in RFC 8707, this parameter is used to request access tokens with a specific scope for a particular
	/// resource.
	/// </summary>
	[BindProperty(SupportsGet = true, Name = Parameters.Resource)]
	public Uri[]? Resources { get; set; }

	public Core.AuthorizationRequest Map() => new()
	{
		Nonce = Nonce,
		Claims = Claims,
		Display = Display,
		Prompt = Prompt,
		Scope = Scope,
		State = State,
		AcrValues = AcrValues,
		ClientId = ClientId,
		CodeChallenge = CodeChallenge,
		LoginHint = LoginHint,
		MaxAge = MaxAge,
		RedirectUri = RedirectUri,
		Request = Request,
		RequestUri = RequestUri,
		ResponseMode = ResponseMode,
		ResponseType = ResponseType,
		UiLocales = UiLocales,
		CodeChallengeMethod = CodeChallengeMethod,
		IdTokenHint = IdTokenHint,
		ClaimsLocales = ClaimsLocales,
		Resources = Resources,
	};
}
