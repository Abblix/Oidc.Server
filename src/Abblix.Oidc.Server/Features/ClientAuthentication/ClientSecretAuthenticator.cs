// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Serves as a base class for client authentication, utilizing client ID and secret. It validates
/// clients against a known list of clients, ensuring that the client secret provided during the authentication
/// process matches the stored secret for the client. This class supports various hash algorithms for
/// secure secret comparison and handles client secret expiration.
/// </summary>
public abstract partial class ClientSecretAuthenticator(
	ILogger<ClientSecretAuthenticator> logger,
	TimeProvider clock,
	IHashService hashService)
{
	private readonly ClientSecretMatcher _matcher = new(hashService);

	/// <summary>
	/// Asynchronously authenticates a client using provided credentials. It validates the client ID and secret
	/// against stored values, considering the authentication method and secret expiration.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at; the client is looked up there alone.</param>
	/// <param name="clients">The clients of the request being served, where the client is looked up.</param>
	/// <param name="clientId">Client ID for identification.</param>
	/// <param name="secret">Client secret for verification.</param>
	/// <param name="authenticationMethod">Authentication method used, ensuring compatibility with client configuration.</param>
	/// <returns>
	/// Authenticated client information if successful; otherwise, the refusal of a credential presented and not valid.
	/// </returns>
	protected async Task<Result<ClientInfo, OidcError>> TryAuthenticateAsync(
		TenantDefinition tenant,
		IClientInfoProvider clients,
		string? clientId,
		[Credential] string? secret,
		string authenticationMethod)
	{
		if (!clientId.NotNullOrWhiteSpace() || !secret.NotNullOrWhiteSpace())
		{
			return ClientAuthenticationFailures.InvalidCredential;
		}

		if (!(await clients.FindClientAsync(tenant, clientId)).TryGetSuccess(out var client))
		{
			LogClientNotFound(clientId);
			return ClientAuthenticationFailures.InvalidCredential;
		}

		if (!authenticationMethod.Equals(client.TokenEndpointAuthMethod, StringComparison.Ordinal)) {
			LogWrongAuthMethod(clientId);
			return ClientAuthenticationFailures.InvalidCredential;
		}

		if (client is not { ClientSecrets.Length: > 0 })
		{
			LogNoSecretsConfigured(clientId);
			return ClientAuthenticationFailures.InvalidCredential;
		}

		if (!TryValidateClientSecret(client, secret))
		{
			return ClientAuthenticationFailures.InvalidCredential;
		}

		return client;
	}

	/// <summary>
	/// Validates a provided client secret against stored secrets for a given client. This method supports
	/// secure comparison by hashing the provided secret and comparing it with stored hashes.
	/// </summary>
	/// <param name="client">The client whose secret is to be validated.</param>
	/// <param name="secret">The secret provided for validation.</param>
	/// <returns>
	/// True if the secret matches a stored hash and is not expired; otherwise, false.
	/// </returns>
	private bool TryValidateClientSecret(ClientInfo client, [Credential] string secret)
	{
		var matchingSecret = _matcher.FindMatching(client, secret).MaxBy(item => item.ExpiresAt);

		if (matchingSecret == null)
		{
			LogNoMatchingSecret(client.ClientId);
			return false; // Invalid secret
		}

		if (matchingSecret.ExpiresAt.HasValue && matchingSecret.ExpiresAt.Value < clock.GetUtcNow())
		{
			LogSecretExpired(client.ClientId);
			return false; // Secret is expired
		}

		LogAuthenticated(client.ClientId);
		return true;
	}
}
