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
/// authenticator instead self-selects by recognizing its own credential form. client_secret_jwt and private_key_jwt
/// read the same parameter, so each claims an assertion signed with its own algorithms, private_key_jwt also one signed
/// with no method's, and answers the rest as presenting no credential: one of them judges and logs each signed
/// assertion (<see cref="ClientAssertionSigning"/>). See the rationale
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
	/// <param name="clients">The clients of the request being served, where the client is looked up.</param>
	/// <returns><see cref="ClientAuthenticationFailures.MoreThanOneMethod"/> for a request presenting credentials in
	/// more than one place, before any authenticator checks one; otherwise the client the first authenticator to
	/// succeed proves, where a credential is presented only those reading it being asked; otherwise the refusal of the
	/// first one a credential was presented to, or, where none was presented to any,
	/// <see cref="ClientAuthenticationFailures.NoCredential"/>.
	/// </returns>
	public async Task<Result<ClientInfo, OidcError>> TryAuthenticateClientAsync(
		TenantDefinition tenant,
		ClientRequest request,
		IClientInfoProvider clients)
	{
		var presented = new HashSet<string>(StringComparer.Ordinal);
		var readingIt = new List<IClientAuthenticator>();
		foreach (var clientAuthenticator in clientAuthenticators)
		{
			var places = (await clientAuthenticator.FindPresentedCredentialsAsync(tenant, request, clients)).ToArray();
			if (places.Length == 0)
				continue;

			presented.UnionWith(places);
			readingIt.Add(clientAuthenticator);
		}

		// RFC 6749 section 2.3: "The client MUST NOT use more than one authentication method in each request". Asked
		// before any authenticator runs, so a request refused for it has no secret compared and no assertion spent
		if (presented.Count > 1)
			return ClientAuthenticationFailures.MoreThanOneMethod;

		// A presented credential is answered by the authenticators reading it alone. The none one reads nothing and
		// would serve a public client on its client_id over the refusal of the credential it did present, while
		// OpenID Connect Core 1.0 section 9 gives none only to "a Public Client with no Client Secret or other
		// authentication mechanism" and RFC 6749 section 5.2 answers an "unsupported authentication method" with
		// invalid_client
		var asked = presented.Count > 0 ? readingIt.ToArray() : clientAuthenticators;

		OidcError? refused = null;
		foreach (var clientAuthenticator in asked)
		{
			var result = await clientAuthenticator.TryAuthenticateClientAsync(tenant, request, clients);
			if (result.TryGetSuccess(out var clientInfo))
				return clientInfo;

			if (result.GetFailure() is not UnauthenticatedCallerError)
				refused ??= result.GetFailure();
		}

		return refused ?? ClientAuthenticationFailures.NoCredential;
	}

	/// <summary>
	/// Every place a credential is presented in that any authenticator reads, each named once, so a credential two
	/// authenticators read counts as one.
	/// </summary>
	public async Task<IEnumerable<string>> FindPresentedCredentialsAsync(
		TenantDefinition tenant,
		ClientRequest request,
		IClientInfoProvider clients)
	{
		var presented = new HashSet<string>(StringComparer.Ordinal);
		foreach (var clientAuthenticator in clientAuthenticators)
			presented.UnionWith(await clientAuthenticator.FindPresentedCredentialsAsync(tenant, request, clients));

		return presented;
	}
}
