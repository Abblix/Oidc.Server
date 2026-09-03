// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;

/// <summary>
/// Result of a successful RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0 section 3).
/// Carries the post-logout redirect target (with <c>state</c> already appended when present)
/// and the set of front-channel logout URIs the user agent must visit so each affected
/// client can clear its own session.
/// </summary>
public record EndSessionSuccess(Uri? PostLogoutRedirectUri, IList<Uri> FrontChannelLogoutRequestUris)
{
	/// <summary>
	/// Validated <c>post_logout_redirect_uri</c> with <c>state</c> appended when supplied,
	/// or <c>null</c> when the client did not request one (the OP then renders its own
	/// "logged out" page).
	/// </summary>
	public Uri? PostLogoutRedirectUri { get; init; } = PostLogoutRedirectUri;

	/// <summary>
	/// Front-channel logout URIs (OpenID Connect Front-Channel Logout 1.0) collected from
	/// every client that participated in the ended session, to be loaded in the user agent
	/// so each RP can clear local state.
	/// </summary>
	public IList<Uri> FrontChannelLogoutRequestUris { get; init; } = FrontChannelLogoutRequestUris;
}
