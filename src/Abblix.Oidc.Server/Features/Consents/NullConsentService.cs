// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Default no-op consent provider that auto-grants every requested scope and resource and never marks
/// consent as pending. Suitable for trusted first-party deployments and as the starting placeholder
/// during integration; replace with a host-supplied implementation to honour OIDC Core section 3.1.2.4
/// (authorization server obtains end-user consent).
/// </summary>
public class NullConsentService : IUserConsentsProvider
{
	/// <summary>
	/// Returns a <see cref="UserConsents"/> with every requested scope and resource pre-granted and
	/// nothing pending, so the authorization flow can proceed without prompting the user.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at, which grants alike at every tenant.</param>
	/// <param name="request">The validated authorization request for which to retrieve consents.</param>
	/// <param name="authSession">The authentication session associated with the request.</param>
	public Task<UserConsents> GetUserConsentsAsync(
		TenantDefinition tenant, ValidAuthorizationRequest request, AuthSession authSession)
	{
		var userConsents = new UserConsents
		{
			GivenWithoutEndUser = true,
			Granted = new(request.Scope, request.Resources)
			{
				AuthorizationDetails = request.AuthorizationDetails,
			},
		};
		return Task.FromResult(userConsents);
	}
}
