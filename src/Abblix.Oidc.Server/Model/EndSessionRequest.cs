// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using System.Text.Json.Serialization;
using Abblix.Oidc.Server.DeclarativeBinding;


namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Parameters of an RP-initiated logout request to the OpenID Provider's <c>end_session_endpoint</c>,
/// as defined in OpenID Connect RP-Initiated Logout 1.0.
/// </summary>
public record EndSessionRequest
{
	/// <summary>
	/// Wire-level parameter names accepted at the OP's <c>end_session_endpoint</c>
	/// (OpenID Connect RP-Initiated Logout 1.0).
	/// </summary>
	public static class Parameters
	{
		/// <summary>The <c>id_token_hint</c> end-session request parameter carrying a previously issued
		/// ID Token that identifies the end-user being logged out.</summary>
		public const string IdTokenHint = "id_token_hint";

		/// <summary>The <c>logout_hint</c> end-session request parameter; an opaque hint about the
		/// end-user's login identifier when no ID Token hint is available.</summary>
		public const string LogoutHint = "logout_hint";

		/// <summary>The <c>client_id</c> end-session request parameter identifying the relying party.
		/// </summary>
		public const string ClientId = "client_id";

		/// <summary>The <c>post_logout_redirect_uri</c> end-session request parameter naming the URI the
		/// user agent is redirected to after logout completes.</summary>
		public const string PostLogoutRedirectUri = "post_logout_redirect_uri";

		/// <summary>The <c>state</c> end-session request parameter; an opaque value echoed back on the
		/// post-logout redirect for correlation.</summary>
		public const string State = "state";

		/// <summary>The <c>ui_locales</c> end-session request parameter listing preferred UI locales for
		/// the logout confirmation page.</summary>
		public const string UiLocales = "ui_locales";

		/// <summary>The end-session field carrying the value the OP issued when it asked the end user whether to
		/// log out, sent back with their answer.</summary>
		public const string Confirmation = "confirmation";
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
	[CultureList]
	public IEnumerable<CultureInfo>? UiLocales { get; set; }

	/// <summary>
	/// Carries the End-User's answer to the logout question the OP is required to ask per OIDC RP-Initiated
	/// Logout 1.0 section 2 ("the OP SHOULD ask the End-User whether to log out ... MUST ask ... if an
	/// id_token_hint was not provided"). It holds the value the OP issued when it asked, which the host renders
	/// into its page and sends back with the answer; the OP spends it and ends the session it was issued for.
	/// </summary>
	/// <remarks>
	/// The answer is this value rather than a flag because a flag states itself: any site could send one and end
	/// the session, which section 6 names as a denial of service. Not a wire parameter defined by the
	/// specification, which leaves the exchange between the OP and its own pages unspecified.
	/// </remarks>
	[JsonPropertyName(Parameters.Confirmation)]
	public string? Confirmation { get; set; }
}
