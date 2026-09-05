// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
		var userConsents = new UserConsents
		{
			Granted = new(request.Scope, request.Resources)
			{
				AuthorizationDetails = request.AuthorizationDetails,
			},
		};
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
