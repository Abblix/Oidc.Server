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

using System.Text;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Clock;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Implements an authentication of a client request by HTTP 'Authorization' header using the 'Basic' scheme.
/// This authentication method follows the standards outlined in RFC 7617.
/// </summary>
public class ClientSecretBasicAuthenticator : ClientSecretAuthenticator, IClientAuthenticator
{
	/// <summary>
	/// Initializes a new instance of the <see cref="ClientSecretBasicAuthenticator"/> class.
	/// </summary>
	/// <param name="logger">Logger for logging authentication-related information and errors.</param>
	/// <param name="clientInfoProvider">The provider for client information retrieval.</param>
	/// <param name="clock">The clock instance for time-related operations.</param>
	/// <param name="hashService">The client secret hasher for verifying client secrets.</param>
	public ClientSecretBasicAuthenticator(
		ILogger<ClientSecretBasicAuthenticator> logger,
		IClientInfoProvider clientInfoProvider,
		IClock clock, IHashService hashService)
		: base(logger, clientInfoProvider, clock, hashService)
	{
	}

	/// <summary>
	/// Specifies the client authentication method this authenticator supports, which is 'client_secret_basic'.
	/// This indicates that the authenticator handles client authentication using the Basic Authentication scheme,
	/// as defined in RFC 7617, where the client ID and secret are passed in the 'Authorization' header
	/// encoded in Base64 format.
	/// </summary>
	public IEnumerable<string> ClientAuthenticationMethodsSupported
	{
		get { yield return ClientAuthenticationMethods.ClientSecretBasic; }
	}

	/// <summary>
	/// Tries to authenticate a client based on the 'Basic' authentication scheme.
	/// This method extracts the Base64-encoded credentials from the 'Authorization' header of the request, decodes them,
	/// and attempts to authenticate the client using the extracted credentials.
	/// It adheres to the user-id and password format as outlined in RFC 7617, Section 2.1, where the first colon in the
	/// credentials string separates the user-id (client ID) and the password (client secret).
	/// </summary>
	/// <param name="request">
	/// The client request containing the authentication information in the 'Authorization' header.
	/// </param>
	/// <returns>
	/// A <see cref="Task"/> representing the asynchronous operation, which upon completion will yield the authenticated
	/// <see cref="ClientInfo"/> or null if authentication fails.
	/// If the 'Authorization' header is missing, malformed, or does not follow the Basic authentication scheme,
	/// the method returns null.
	/// </returns>
	public async Task<ClientInfo?> TryAuthenticateClientAsync(ClientRequest request)
	{
		if (request.AuthorizationHeader is not { Scheme: "Basic", Parameter: { } parameter })
			return null;

		var value = Encoding.ASCII.GetString(Convert.FromBase64String(parameter));

		// According to RFC 7617: https://www.rfc-editor.org/rfc/rfc7617#section-2.1
		// the first colon in a user-pass string separates user-id and password from one another;
		// text after the first colon is part of the password.
		// User-ids containing colons cannot be encoded in user-pass strings.
		var colonIndex = value.IndexOf(':');
		if (colonIndex < 0)
			return null;

		return await TryAuthenticateAsync(
			clientId: value[..colonIndex],
			secret: value[(colonIndex + 1)..],
			ClientAuthenticationMethods.ClientSecretBasic);
	}
}
