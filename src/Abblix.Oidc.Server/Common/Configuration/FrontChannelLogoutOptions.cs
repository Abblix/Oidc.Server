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

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Front-channel logout settings for a single client, as defined by the OpenID Connect Front-Channel Logout 1.0
/// specification. Tells the authorization server which URL to load in a hidden iframe during end-session
/// processing and whether the iframe URL must carry the user's session identifier.
/// </summary>
/// <param name="Uri">The client's front-channel logout endpoint, loaded in a hidden iframe at the OP.</param>
/// <param name="RequiresSessionId">
/// When <c>true</c>, the OP appends <c>iss</c> and <c>sid</c> query parameters to <paramref name="Uri"/>
/// so the client can scope the logout to the correct session.
/// </param>
public record FrontChannelLogoutOptions(Uri Uri, bool RequiresSessionId = true);
