// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Aggregates multiple client authentication strategies into a single composite authenticator.
/// This class allows for attempting client authentication through a sequence of different
/// authentication methods, providing flexibility in supporting multiple authentication protocols.
/// </summary>
/// <remarks>
/// This is intentionally a try-each composite rather than keyed-name DI by
/// <c>token_endpoint_auth_method</c>: that method is not a discriminator present in the token
/// request (it is the client's registered metadata), so it cannot be keyed on directly - each
/// authenticator instead self-selects by recognizing its own credential form. See the rationale
/// at <see cref="ClientAuthenticationServiceCollectionExtensions.AddClientAuthentication"/>.
/// </remarks>
internal class CompositeClientAuthenticator(params IClientAuthenticator[] clientAuthenticators)
	: IClientAuthenticator
{
	/// <summary>
	/// Gets a collection of strings representing the client authentication methods supported by the implementation.
	/// This can include methods such as client_secret_basic, client_secret_post, private_key_jwt, etc.
	/// </summary>
	public IEnumerable<string> ClientAuthenticationMethodsSupported =>
		from authenticator in clientAuthenticators
		from method in authenticator.ClientAuthenticationMethodsSupported
		select method;

	/// <summary>
	/// Attempts to authenticate a client request by sequentially invoking each registered authenticator
	/// until one succeeds or all fail.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at, handed to each authenticator.</param>
	/// <param name="request">The <see cref="ClientRequest"/> to authenticate. This object contains details
	/// about the request that may be used by authenticators to determine the client's identity.</param>
	/// <returns>The client the first authenticator to succeed proves; otherwise the refusal of the first one a
	/// credential was presented to, or, where none was presented to any, <see cref="ClientAuthenticationFailures.NoCredential"/>.
	/// </returns>
	public async Task<Result<ClientInfo, OidcError>> TryAuthenticateClientAsync(TenantDefinition tenant, ClientRequest request)
	{
		OidcError? refused = null;
		foreach (var clientAuthenticator in clientAuthenticators)
		{
			var result = await clientAuthenticator.TryAuthenticateClientAsync(tenant, request);
			if (result.TryGetSuccess(out var clientInfo))
				return clientInfo;

			if (result.GetFailure() is not UnauthenticatedCallerError)
				refused ??= result.GetFailure();
		}

		return refused ?? ClientAuthenticationFailures.NoCredential;
	}
}
