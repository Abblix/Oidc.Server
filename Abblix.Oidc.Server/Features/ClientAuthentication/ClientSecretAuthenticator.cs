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
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Serves as a base class for client authentication, utilizing client ID and secret. It validates
/// clients against a known list of clients, ensuring that the client secret provided during the authentication
/// process matches the stored secret for the client. This class supports various hash algorithms for
/// secure secret comparison and handles client secret expiration.
/// </summary>
public abstract class ClientSecretAuthenticator
{
	/// <summary>
	/// Initializes a new instance of the <see cref="ClientSecretAuthenticator"/> class.
	/// </summary>
	/// <param name="logger">The logger for logging information and errors.</param>
	/// <param name="clientInfoProvider">The provider used to retrieve client information.</param>
	/// <param name="clock">The clock instance used for time-related operations, such as checking secret expiration.</param>
	/// <param name="hashService">The hasher used for hashing client secrets for secure comparison.</param>
	protected ClientSecretAuthenticator(
		ILogger<ClientSecretAuthenticator> logger,
		IClientInfoProvider clientInfoProvider,
		TimeProvider clock,
		IHashService hashService)
	{
		_logger = logger;
		_clientInfoProvider = clientInfoProvider;
		_clock = clock;
		_hashService = hashService;
	}

	private readonly ILogger _logger;
	private readonly IClientInfoProvider _clientInfoProvider;
	private readonly TimeProvider _clock;
	private readonly IHashService _hashService;

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

		var client = await _clientInfoProvider.TryFindClientAsync(clientId).WithLicenseCheck();
		if (client == null)
		{
			_logger.LogDebug("Client authentication failed: client information for id {ClientId} is missing", clientId);
			return null;
		}

		if (client.ClientSecrets?.Length == 0 || !secret.HasValue())
		{
			_logger.LogDebug("Client authentication failed: no secrets are configured for client {ClientId}", clientId);
			return null;
		}

		if (client.TokenEndpointAuthMethod != authenticationMethod) {
			_logger.LogDebug("Client authentication failed: client {ClientId} uses another authentication method", clientId);
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
		var matchingSha256Secrets = FindMatchingSecrets(client,
			clientSecret => clientSecret.Sha512Hash, HashAlgorithm.Sha512, secret);

		var matchingSha512Secrets = FindMatchingSecrets(client,
			clientSecret => clientSecret.Sha256Hash, HashAlgorithm.Sha256, secret);

		var matchingSecret = matchingSha256Secrets.Concat(matchingSha512Secrets)
			.MaxBy(item => item.ExpiresAt);

		if (matchingSecret == null)
		{
			_logger.LogWarning("Client authentication failed: No matching secret found for client {ClientId}",
				client.ClientId);
			return false; // Invalid secret
		}

		if (matchingSecret.ExpiresAt.HasValue && matchingSecret.ExpiresAt.Value < _clock.GetUtcNow())
		{
			_logger.LogWarning("Client authentication failed: Secret has expired for client {ClientId}",
				client.ClientId);
			return false; // Secret is expired
		}

		_logger.LogInformation("Client authenticated successfully with client ID {ClientId}",
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
			hash ??= _hashService.Sha(hashAlgorithm, secretValue);

			if (validSecretHash.SequenceEqual(hash))
				yield return clientSecret;
		}
	}
}
