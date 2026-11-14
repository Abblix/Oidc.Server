// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;



namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Validates a username and password pair against the host's user store and produces an authorized grant
/// when the credentials are correct. Used by the Resource Owner Password Credentials grant
/// (<c>grant_type=password</c>) at the token endpoint, so the host can plug its own identity backend
/// behind the OAuth flow.
/// </summary>
/// <remarks>
/// The users stay the host's, and the server asks the same authenticator for every tenant, handing it the tenant
/// the token is requested at. A host whose tenants keep users apart checks the credentials against that tenant's
/// users, so a user name one tenant knows is not taken for the same name at another.
/// </remarks>
public interface IUserCredentialsAuthenticator
{
	/// <summary>
	/// Validates user credentials (username and password) and returns a grant authorization result.
	/// </summary>
	/// <param name="tenant">The tenant the token is requested at.</param>
	/// <param name="userName">The username provided by the user.</param>
	/// <param name="password">The password provided by the user.</param>
	/// <param name="context">The authorization context associated with the request.</param>
	/// <returns>A task that represents the asynchronous validation operation and returns the grant authorization result.</returns>
	Task<Result<AuthorizedGrant, OidcError>> ValidateAsync(
		TenantDefinition tenant, string userName, string password, AuthorizationContext context);
}
