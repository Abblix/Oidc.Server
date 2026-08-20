// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
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
/// authenticator instead self-selects by recognising its own credential form. See the rationale
/// at <see cref="ServiceCollectionExtensions.AddClientAuthentication"/>.
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
	/// <param name="request">The <see cref="ClientRequest"/> to authenticate. This object contains details
	/// about the request that may be used by authenticators to determine the client's identity.</param>
	/// <returns>
	/// A <see cref="Task"/> representing the asynchronous operation. The task result is a <see cref="ClientInfo"/>
	/// object representing the authenticated client if authentication is successful; otherwise, <c>null</c>.
	/// </returns>
	/// <remarks>
	/// This method provides a unified interface for client authentication, simplifying the process
	/// of supporting multiple authentication mechanisms. It iterates through the provided authenticators
	/// and returns the first successful authentication result, or <c>null</c> if no authenticator succeeds.
	/// </remarks>
	public async Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request)
	{
		foreach (var clientAuthenticator in clientAuthenticators)
		{
			var clientInfo = await clientAuthenticator.TryAuthenticateClientAsync(request);
			if (clientInfo != null)
				return clientInfo;
		}

		return null;
	}
}
