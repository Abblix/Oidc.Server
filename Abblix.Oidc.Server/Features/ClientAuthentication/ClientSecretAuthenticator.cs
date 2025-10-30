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
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using static Abblix.Utils.Sanitized;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Serves as a base class for client authentication, utilizing client ID and secret. It validates
/// clients against a known list of clients, ensuring that the client secret provided during the authentication
/// process matches the stored secret for the client. This class supports various hash algorithms for
/// secure secret comparison and handles client secret expiration.
/// </summary>
public abstract class ClientSecretAuthenticator(
	ILogger<ClientSecretAuthenticator> logger,
	IClientInfoProvider clientInfoProvider,
	TimeProvider clock,
	IHashService hashService)
{

	/// <summary>
	/// Asynchronously authenticates a client using provided credentials. It validates the client ID and secret
	/// against stored values, considering the authentication method and secret expiration.
	/// </summary>
	/// <param name="clientId">Client ID for identification.</param>
	/// <param name="secret">Client secret for verification.</param>
	/// <param name="authenticationMethod">Authentication method used, ensuring compatibility with client configuration.</param>
	/// <returns>
	/// Authenticated client information if successful; otherwise, null.
	/// </returns>
	protected async Task<ClientInfo?> TryAuthenticateAsync(string? clientId, string? secret, string authenticationMethod)
	{
		if (clientId == null)
		{
			return null;
		}

		var client = await clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
		if (client == null)
		{
			logger.LogDebug("Client authentication failed: client information for id {ClientId} is missing", Value(clientId));
			return null;
		}

		if (client.ClientSecrets?.Length == 0 || !secret.HasValue())
		{
			logger.LogDebug("Client authentication failed: no secrets are configured for client {ClientId}", Value(clientId));
			return null;
		}

		if (client.TokenEndpointAuthMethod != authenticationMethod) {
			logger.LogDebug("Client authentication failed: client {ClientId} uses another authentication method", Value(clientId));
			return null;
		}

		if (!TryValidateClientSecret(client, secret))
		{
			return null;
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
	private bool TryValidateClientSecret(ClientInfo client, string secret)
	{
		// We store only client secret hashes, so we have to hash the raw secret to compare. And we do it lazy.
		var matchingSha512Secrets = FindMatchingSecrets(
			client, clientSecret => clientSecret.Sha512Hash, HashAlgorithm.Sha512, secret);

		var matchingSha256Secrets = FindMatchingSecrets(
			client, clientSecret => clientSecret.Sha256Hash, HashAlgorithm.Sha256, secret);

		var matchingSecret = matchingSha512Secrets.Concat(matchingSha256Secrets)
			.MaxBy(item => item.ExpiresAt);

		if (matchingSecret == null)
		{
			logger.LogWarning("Client authentication failed: No matching secret found for client {ClientId}",
				client.ClientId);
			return false; // Invalid secret
		}

		if (matchingSecret.ExpiresAt.HasValue && matchingSecret.ExpiresAt.Value < clock.GetUtcNow())
		{
			logger.LogWarning("Client authentication failed: Secret has expired for client {ClientId}",
				client.ClientId);
			return false; // Secret is expired
		}

		logger.LogInformation("Client authenticated successfully with client ID {ClientId}",
			client.ClientId);
		return true;
	}

	/// <summary>
	/// Identifies stored secrets that match a provided secret value for a client. It hashes the provided
	/// secret using the specified algorithm and compares it against stored hashes.
	/// </summary>
	/// <param name="client">Client owning the secrets.</param>
	/// <param name="hashSelector">Function selecting the hash from a client secret.</param>
	/// <param name="hashAlgorithm">Algorithm used for hashing the provided secret.</param>
	/// <param name="secretValue">Secret value to hash and compare.</param>
	/// <returns>
	/// Enumerable of matching client secrets.
	/// </returns>
	private IEnumerable<ClientSecret> FindMatchingSecrets(
		ClientInfo client,
		Func<ClientSecret, byte[]?> hashSelector,
		HashAlgorithm hashAlgorithm,
		string secretValue)
	{
		var validSecretHashes =
			from clientSecret in client.ClientSecrets
			let secretHash = hashSelector(clientSecret)
			where secretHash != null
			select (clientSecret, secretHash);

		byte[]? hash = null;
		foreach (var (clientSecret, validSecretHash) in validSecretHashes)
		{
			hash ??= hashService.Sha(hashAlgorithm, secretValue);

			if (validSecretHash.SequenceEqual(hash))
				yield return clientSecret;
		}
	}
}
