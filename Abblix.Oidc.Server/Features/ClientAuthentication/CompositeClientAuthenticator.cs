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

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Aggregates multiple client authentication strategies into a single composite authenticator.
/// This class allows for attempting client authentication through a sequence of different
/// authentication methods, providing flexibility in supporting multiple authentication protocols.
/// </summary>
internal class CompositeClientAuthenticator(params IClientAuthenticator[] clientAuthenticators) : IClientAuthenticator
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
