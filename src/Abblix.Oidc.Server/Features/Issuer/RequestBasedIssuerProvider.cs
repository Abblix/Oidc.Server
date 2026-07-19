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

using Abblix.Oidc.Server.Common.Interfaces;

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// Dynamically determines the issuer identifier based on the incoming HTTP request.
/// This approach allows the issuer identifier to reflect the actual request's context,
/// accommodating scenarios like varying host names or different environments.
/// </summary>
internal class RequestBasedIssuerProvider(IRequestInfoProvider requestInfoProvider) : IIssuerProvider
{
	/// <summary>
	/// Retrieves the issuer identifier based on the current HTTP request.
	/// </summary>
	/// <returns>The issuer identifier, constructed from the request's context.</returns>
	public string GetIssuer() => requestInfoProvider.ApplicationUri;
}
