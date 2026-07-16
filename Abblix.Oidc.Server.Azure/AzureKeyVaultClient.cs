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

using System.Collections.Concurrent;
using System.Security.Cryptography;
using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Azure;

/// <summary>
/// Thin wrapper over the Azure Key Vault SDK. Signing and unwrapping run inside the vault against a key whose
/// private half never leaves it, so this type only moves bytes across the boundary. A
/// <see cref="CryptographyClient"/> is cached per key name because creating one resolves the key's metadata on
/// first use.
/// </summary>
public sealed class AzureKeyVaultClient
{
    private readonly Uri _vaultUri;
    private readonly TokenCredential _credential;
    private readonly KeyClient _keyClient;
    private readonly ConcurrentDictionary<string, CryptographyClient> _cryptographyClients = new();

    /// <summary>
    /// Creates the client for the vault named by <paramref name="options"/>, selecting a client-secret
    /// credential when the service-principal fields are set, or the default Azure credential chain otherwise.
    /// </summary>
    /// <param name="options">The configured Azure Key Vault options.</param>
    public AzureKeyVaultClient(IOptions<AzureKeyVaultOptions> options)
    {
        var settings = options.Value;
        _vaultUri = new Uri(settings.KeyVaultUri);

        // Use explicit service-principal credentials from configuration when all three are set; otherwise fall
        // back to DefaultAzureCredential, which covers a managed identity, an Azure CLI sign-in, or the AZURE_*
        // environment variables. Production on Azure uses a managed identity and needs none of these set.
        _credential = !string.IsNullOrWhiteSpace(settings.TenantId)
                && !string.IsNullOrWhiteSpace(settings.ClientId)
                && !string.IsNullOrWhiteSpace(settings.ClientSecret)
            ? new ClientSecretCredential(settings.TenantId, settings.ClientId, settings.ClientSecret)
            : new DefaultAzureCredential();

        _keyClient = new KeyClient(_vaultUri, _credential);
    }

    /// <summary>
    /// Signs the JWS signing input with a Key Vault RSA key. RS256 is signed over the data (the vault hashes
    /// it), and Key Vault returns the raw signature already in JWS wire format.
    /// </summary>
    public async Task<byte[]> SignAsync(string keyName, byte[] data, CancellationToken cancellationToken)
    {
        var result = await GetCryptographyClient(keyName).SignDataAsync(SignatureAlgorithm.RS256, data, cancellationToken);
        return result.Signature;
    }

    /// <summary>
    /// Unwraps (decrypts) an RSA-OAEP-256 CEK with a Key Vault RSA key. Key Vault decrypts a raw JWE ciphertext
    /// directly. Returns null on failure so a wrong key or tampered ciphertext is indistinguishable, which the
    /// seam's padding-oracle mitigation relies on.
    /// </summary>
    public async Task<byte[]?> DecryptAsync(string keyName, byte[] ciphertext, CancellationToken cancellationToken)
    {
        try
        {
            var result = await GetCryptographyClient(keyName).DecryptAsync(EncryptionAlgorithm.RsaOaep256, ciphertext, cancellationToken);
            return result.Plaintext;
        }
        catch (RequestFailedException)
        {
            return null;
        }
    }

    /// <summary>
    /// Fetches the public half of a Key Vault key as RSA parameters. Called once per key at startup, so JWKS
    /// publishing and signature verification run locally against it and never touch the vault on the hot path.
    /// </summary>
    public async Task<RSAParameters> GetPublicKeyAsync(string keyName, CancellationToken cancellationToken)
    {
        var key = await _keyClient.GetKeyAsync(keyName, cancellationToken: cancellationToken);
        using var rsa = key.Value.Key.ToRSA();
        return rsa.ExportParameters(false);
    }

    private CryptographyClient GetCryptographyClient(string keyName)
        => _cryptographyClients.GetOrAdd(keyName,
            name => new CryptographyClient(new Uri($"{_vaultUri}keys/{name}"), _credential));
}
