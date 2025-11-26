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

using System.Text;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Implements an authentication of a client request by HTTP 'Authorization' header using the 'Basic' scheme.
/// This authentication method follows the standards outlined in RFC 7617.
/// </summary>
public class ClientSecretBasicAuthenticator(
	ILogger<ClientSecretBasicAuthenticator> logger,
	IClientInfoProvider clientInfoProvider,
	TimeProvider clock,
	IHashService hashService)
	: ClientSecretAuthenticator(logger, clientInfoProvider, clock, hashService), IClientAuthenticator
{
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
