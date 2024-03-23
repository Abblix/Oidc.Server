// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
