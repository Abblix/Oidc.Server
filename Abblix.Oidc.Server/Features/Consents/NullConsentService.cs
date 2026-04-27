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
/// Default no-op consent provider that auto-grants every requested scope and resource and never marks
/// consent as pending. Suitable for trusted first-party deployments and as the starting placeholder
/// during integration; replace with a host-supplied implementation to honour OIDC Core §3.1.2.4
/// (authorization server obtains end-user consent).
/// </summary>
public class NullConsentService : IUserConsentsProvider
{
	/// <summary>
	/// Returns a <see cref="UserConsents"/> with every requested scope and resource pre-granted and
	/// nothing pending, so the authorization flow can proceed without prompting the user.
	/// </summary>
	/// <param name="request">The validated authorization request for which to retrieve consents.</param>
	/// <param name="authSession">The authentication session associated with the request.</param>
	public Task<UserConsents> GetUserConsentsAsync(ValidAuthorizationRequest request, AuthSession authSession)
	{
		var userConsents = new UserConsents { Granted = new(request.Scope, request.Resources) };
		return Task.FromResult(userConsents);
	}

	/// <summary>
	/// Returns <c>false</c> for every request because <see cref="GetUserConsentsAsync"/> grants
	/// everything up-front and leaves <see cref="UserConsents.Pending"/> empty.
	/// </summary>
	/// <param name="request">The validated authorization request that might require consent.</param>
	/// <param name="authSession">The authentication session associated with the request.</param>
	public async Task<bool> IsConsentRequired(ValidAuthorizationRequest request, AuthSession authSession)
	{
		var userConsents = await GetUserConsentsAsync(request, authSession);
		return userConsents.Pending is { Scopes.Length: > 0 } or { Resources.Length: > 0 };
	}
}
