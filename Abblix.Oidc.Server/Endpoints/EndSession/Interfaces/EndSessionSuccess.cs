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

namespace Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;

/// <summary>
/// Result of a successful RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0 §3).
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
