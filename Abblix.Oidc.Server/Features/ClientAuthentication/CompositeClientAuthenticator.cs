// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Aggregates multiple client authentication strategies into a single composite authenticator.
/// This class allows for attempting client authentication through a sequence of different
/// authentication methods, providing flexibility in supporting multiple authentication protocols.
/// </summary>
internal class CompositeClientAuthenticator : IClientAuthenticator
{
	/// <summary>
	/// Initializes a new instance of the <see cref="CompositeClientAuthenticator"/> class.
	/// </summary>
	/// <param name="clientAuthenticators">An array of <see cref="IClientAuthenticator"/> implementations.
	/// These authenticators are used in the order they are provided to attempt client authentication.</param>
	public CompositeClientAuthenticator(params IClientAuthenticator[] clientAuthenticators)
	{
		_clientAuthenticators = clientAuthenticators;
	}

	private readonly IClientAuthenticator[] _clientAuthenticators;

	/// <summary>
	/// Gets a collection of strings representing the client authentication methods supported by the implementation.
	/// This can include methods such as client_secret_basic, client_secret_post, private_key_jwt, etc.
	/// </summary>
	public IEnumerable<string> ClientAuthenticationMethodsSupported =>
		from authenticator in _clientAuthenticators
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
		foreach (var clientAuthenticator in _clientAuthenticators)
		{
			var clientInfo = await clientAuthenticator.TryAuthenticateClientAsync(request);
			if (clientInfo != null)
				return clientInfo;
		}

		return null;
	}
}
