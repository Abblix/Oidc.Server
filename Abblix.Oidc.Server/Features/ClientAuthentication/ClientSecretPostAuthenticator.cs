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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Clock;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Implements an authentication of a client request by extracting client credentials (client_id and client_secret)
/// from the request body. This approach is typically used in OAuth 2.0 client credential flows where the client submits
/// its credentials as part of the request body.
/// </summary>
public class ClientSecretPostAuthenticator : ClientSecretAuthenticator, IClientAuthenticator
{

	/// <summary>
	/// Initializes a new instance of the <see cref="ClientSecretPostAuthenticator"/> class.
	/// </summary>
	/// <param name="logger">Logger for logging authentication-related information and errors.</param>
	/// <param name="clientInfoProvider">The provider for client information retrieval.</param>
	/// <param name="clock">The clock instance for time-related operations, such as checking secret expiration.</param>
	/// <param name="hashService">The client secret hasher used for verifying client secrets in a secure manner.</param>
	public ClientSecretPostAuthenticator(
		ILogger<ClientSecretPostAuthenticator> logger,
		IClientInfoProvider clientInfoProvider,
		IClock clock,
		IHashService hashService)
		: base(logger, clientInfoProvider, clock, hashService)
	{
	}

	/// <summary>
	/// Specifies the client authentication method this authenticator supports, which is 'client_secret_post'.
	/// This property indicates that the authenticator is designed to handle client authentication where the client secret
	/// is sent in the request body parameters. It is a straightforward method for clients to authenticate with the
	/// authorization server by including the client_id and client_secret in the body of the HTTP request.
	/// </summary>
	public IEnumerable<string> ClientAuthenticationMethodsSupported
	{
		get { yield return ClientAuthenticationMethods.ClientSecretPost; }
	}

	/// <summary>
	/// Asynchronously tries to authenticate a client based on credentials (client_id and client_secret) provided in the request body.
	/// The method delegates to <see cref="ClientSecretAuthenticator.TryAuthenticateAsync"/> with the extracted client_id and client_secret.
	/// </summary>
	/// <param name="request">The client request containing the client_id and client_secret for authentication.</param>
	/// <returns>
	/// A <see cref="Task"/> representing the asynchronous operation, which upon completion will yield the authenticated
	/// <see cref="ClientInfo"/> or null if authentication fails.
	/// </returns>
	public async Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request)
	{
		if (!request.ClientId.HasValue() || !request.ClientSecret.HasValue())
			return null;

		return await TryAuthenticateAsync(
			request.ClientId,
			request.ClientSecret,
			ClientAuthenticationMethods.ClientSecretPost);
	}
}
