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
/// Implements the very basic consent service not requiring any consents.
/// </summary>
/// /// <remarks>
/// This implementation assumes that no consents are necessary for any operations, effectively bypassing
/// consent-related checks and workflows. If your application requires user consent for accessing specific scopes
/// or resources, replace this service with a custom implementation that appropriately handles such requirements.
/// </remarks>
public class NullConsentService : IUserConsentsProvider, IConsentService
{
	/// <summary>
	/// Retrieves the user consents for a given authorization request and authentication session.
	/// </summary>
	/// <param name="request">The validated authorization request for which to retrieve consents.</param>
	/// <param name="authSession">The authentication session associated with the request.</param>
	/// <returns>A task that resolves to an instance of <see cref="UserConsents"/>, containing details about
	/// the consents granted by the user. This implementation automatically assumes all consents are granted.</returns>
	public Task<UserConsents> GetUserConsentsAsync(ValidAuthorizationRequest request, AuthSession authSession)
	{
		var userConsents = new UserConsents { Granted = new(request.Scope, request.Resources) };
		return Task.FromResult(userConsents);
	}

	/// <summary>
	/// Determines whether consent is required for a given authorization request and authentication session.
	/// </summary>
	/// <param name="request">The validated authorization request that might require consent.</param>
	/// <param name="authSession">The authentication session associated with the request,
	/// containing user-specific data.</param>
	/// <returns>A task that resolves to a boolean indicating whether user consent is needed. This implementation
	/// always returns false, suggesting consent is never required.</returns>
	public async Task<bool> IsConsentRequired(ValidAuthorizationRequest request, AuthSession authSession)
	{
		var userConsents = await GetUserConsentsAsync(request, authSession);
		return userConsents.Pending is { Scopes.Length: > 0 } or { Resources.Length: > 0 };
	}
}
