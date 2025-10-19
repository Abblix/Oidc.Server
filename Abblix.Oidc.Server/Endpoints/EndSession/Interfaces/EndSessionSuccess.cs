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
/// Represents a successful response for ending a user's session.
/// </summary>
public record EndSessionSuccess(Uri? PostLogoutRedirectUri, IList<Uri> FrontChannelLogoutRequestUris)
{
	/// <summary>
	/// Gets or sets the URI to which the user should be redirected after successfully logging out (optional).
	/// </summary>
	public Uri? PostLogoutRedirectUri { get; init; } = PostLogoutRedirectUri;

	/// <summary>
	/// Gets a list of front-channel logout request URIs to be initiated after logging out.
	/// </summary>
	public IList<Uri> FrontChannelLogoutRequestUris { get; init; } = FrontChannelLogoutRequestUris;
}
