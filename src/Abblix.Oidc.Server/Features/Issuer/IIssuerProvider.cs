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

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// Provides a mechanism to retrieve the issuer identifier for the OpenID Connect provider.
/// The issuer identifier is a fundamental part of the token validation process,
/// as it indicates the origin of the token.
/// </summary>
public interface IIssuerProvider
{
	/// <summary>
	/// Retrieves the issuer identifier that represents the OpenID Connect provider.
	/// This identifier is used in various OpenID Connect responses and tokens to
	/// ensure the identity of the issuing server.
	/// </summary>
	/// <returns>A string representing the issuer identifier.</returns>
	string GetIssuer();
}
