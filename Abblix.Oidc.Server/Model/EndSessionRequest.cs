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
using Abblix.Oidc.Server.DeclarativeValidation;


namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents a request to end a user session, commonly used in OpenID Connect logout scenarios.
/// </summary>
public record EndSessionRequest
{
	public static class Parameters
	{
		public const string IdTokenHint = "id_token_hint";
		public const string LogoutHint = "logout_hint";
		public const string ClientId = "client_id";
		public const string PostLogoutRedirectUri = "post_logout_redirect_uri";
		public const string State = "state";
		public const string UiLocales = "ui_locales";
		public const string Confirmed = "confirmed";
	}

	/// <summary>
	/// The ID token hint. A previously issued ID token passed to the logout endpoint to hint about the End-User's current authenticated session.
	/// </summary>
	[JsonPropertyName(Parameters.IdTokenHint)]
	public string? IdTokenHint { get; set; }

	/// <summary>
	/// The logout hint. An optional parameter used to indicate the login identifier or username the user might have used.
	/// </summary>
	[JsonPropertyName(Parameters.LogoutHint)]
	public string? LogoutHint { get; set; }

	/// <summary>
	/// The client identifier for which the logout request is made.
	/// </summary>
	[JsonPropertyName(Parameters.ClientId)]
	public string? ClientId { get; set; }

	/// <summary>
	/// The state parameter to maintain state between the logout request and the callback to the client after logout.
	/// </summary>
	[JsonPropertyName(Parameters.State)]
	public string? State { get; set; }

	/// <summary>
	/// The URL to which the user should be redirected after logout. This URI must be registered with the authorization server.
	/// </summary>
	[JsonPropertyName(Parameters.PostLogoutRedirectUri)]
	[AbsoluteUri]
	public Uri? PostLogoutRedirectUri { get; set; }

	/// <summary>
	/// The preferred user interface locales for the logout page, represented as a list of <see cref="CultureInfo"/>.
	/// </summary>
	[JsonPropertyName(Parameters.UiLocales)]
	public IEnumerable<CultureInfo>? UiLocales { get; set; }

	/// <summary>
	/// A boolean value indicating whether the end session has been confirmed. Typically used in interactive logout confirmation scenarios.
	/// </summary>
	[JsonPropertyName(Parameters.Confirmed)]
	public bool Confirmed { get; set; }
}
