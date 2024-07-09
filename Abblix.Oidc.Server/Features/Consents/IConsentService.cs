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

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Provides methods to determine whether user consent is to proceed with authentication.
/// </summary>
[Obsolete("Use IConsentProvider instead")]
public interface IConsentService
{
	/// <summary>
	/// Checks if consent is for the given authorization request and authentication session.
	/// </summary>
	/// <param name="request">The authorization request.</param>
	/// <param name="authSession">The authentication session.</param>
	/// <returns>True if consent is required, false otherwise.</returns>
	Task<bool> IsConsentRequired(ValidAuthorizationRequest request, AuthSession authSession);
}
