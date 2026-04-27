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
/// Parameters of an RP-initiated logout request to the OpenID Provider's <c>end_session_endpoint</c>,
/// as defined in OpenID Connect RP-Initiated Logout 1.0.
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
	/// The <c>id_token_hint</c>: a previously issued ID Token whose subject identifies the end-user whose
	/// session should be terminated. Recommended by RP-Initiated Logout to authenticate the logout request
	/// and to scope which session is logged out.
	/// </summary>
	[JsonPropertyName(Parameters.IdTokenHint)]
	public string? IdTokenHint { get; set; }

	/// <summary>
	/// The <c>logout_hint</c>: an opaque hint about the end-user's login identifier (such as username or email)
	/// the OpenID Provider may use to identify the session to terminate when an ID Token hint is unavailable.
	/// </summary>
	[JsonPropertyName(Parameters.LogoutHint)]
	public string? LogoutHint { get; set; }

	/// <summary>
	/// The <c>client_id</c> of the relying party initiating the logout, allowing the OP to validate
	/// <see cref="PostLogoutRedirectUri"/> against the URIs registered for that client.
	/// </summary>
	[JsonPropertyName(Parameters.ClientId)]
	public string? ClientId { get; set; }

	/// <summary>
	/// The opaque <c>state</c> value returned unchanged when the user agent is sent back to
	/// <see cref="PostLogoutRedirectUri"/>, used by the relying party to correlate request and callback.
	/// </summary>
	[JsonPropertyName(Parameters.State)]
	public string? State { get; set; }

	/// <summary>
	/// The <c>post_logout_redirect_uri</c>: an absolute URI, pre-registered with the OP, to which the
	/// user agent is redirected once logout completes.
	/// </summary>
	[JsonPropertyName(Parameters.PostLogoutRedirectUri)]
	[AbsoluteUri]
	public Uri? PostLogoutRedirectUri { get; set; }

	/// <summary>
	/// The <c>ui_locales</c> preference list of BCP 47 language tags hinting how the logout confirmation
	/// page should be localized.
	/// </summary>
	[JsonPropertyName(Parameters.UiLocales)]
	public IEnumerable<CultureInfo>? UiLocales { get; set; }

	/// <summary>
	/// Carries the End-User's answer to the logout confirmation prompt that the OP is required to display
	/// per OIDC RP-Initiated Logout 1.0 §2 ("the OP SHOULD ask the End-User whether to log out ... MUST ask ...
	/// if an id_token_hint was not provided"). When <c>true</c>, the user has explicitly approved logout in
	/// the interactive UI; when <c>null</c> or <c>false</c>, the request is treated as not-yet-confirmed and
	/// the OP renders the confirmation screen. Encoded via the <see cref="Parameters.Confirmed"/> form field
	/// rather than a wire parameter defined by the specification.
	/// </summary>
	[JsonPropertyName(Parameters.Confirmed)]
	public bool? Confirmed { get; set; }
}
