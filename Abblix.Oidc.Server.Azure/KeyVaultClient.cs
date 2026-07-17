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
using System.Net;
using System.Runtime.CompilerServices;
using Abblix.Jwt;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Identity;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

// Azure.Security.KeyVault.Keys also declares a JsonWebKey; alias the namespace so the bare JsonWebKey stays the
// Abblix.Jwt one (which the .Apply extension and the custodian contract need), while KeyClient / KeyType come via KeyVault.
using KeyVault = Azure.Security.KeyVault.Keys;

namespace Abblix.Oidc.Server.Azure;

/// <summary>
/// Thin wrapper over the Azure Key Vault SDK. Signing and unwrapping run inside the vault against a key whose
/// private half never leaves it, so this type only moves bytes across the boundary. The Azure SDK is pointed at
/// the host's <see cref="IHttpClientFactory"/> transport (like the Vault client), so it inherits the host's HTTP
/// handlers, logging and pooling. A <see cref="CryptographyClient"/> is cached per key name because creating one
/// resolves the key's metadata on first use.
/// </summary>
public sealed class KeyVaultClient : IKeyCustodian
{
    private readonly KeyVault.KeyClient _keyClient;
    private readonly ConcurrentDictionary<string, CryptographyClient> _cryptographyClients = new();

    /// <summary>
    /// Creates the client for the vault named by <paramref name="options"/>, selecting a client-secret
    /// credential when the service-principal fields are set, or the default Azure credential chain otherwise.
    /// </summary>
    /// <param name="options">The configured Azure Key Vault options.</param>
    /// <param name="httpClient">The transport for every Key Vault call, supplied by <c>AddHttpClient</c> so the
    /// Azure SDK rides the host's HTTP pipeline.</param>
    [ActivatorUtilitiesConstructor]
    public KeyVaultClient(IOptions<AzureKeyVaultOptions> options, HttpClient httpClient)
        : this(options.Value, BuildCredential(options.Value), httpClient)
    {
    }

    /// <summary>
    /// Builds the client from an explicit credential and transport. This is the seam a test uses to drive the
    /// Azure SDK against a stub <see cref="HttpMessageHandler"/> and a fake credential, so signing, unwrapping and
    /// public-key fetch can be exercised without a live vault.
    /// </summary>
    /// <param name="settings">The Azure Key Vault options.</param>
    /// <param name="credential">The credential the SDK authenticates with.</param>
    /// <param name="httpClient">The transport for every Key Vault call.</param>
    internal KeyVaultClient(AzureKeyVaultOptions settings, TokenCredential credential, HttpClient httpClient)
    {
        // The only client this type builds. Everything else it needs comes off this one: the SDK hands the
        // credential, the options and the pipeline down to the per-key crypto clients, so the injected transport
        // reaches them without being restated, and no key URI is ever composed by hand here.
        _keyClient = new KeyVault.KeyClient(
            settings.KeyVaultUri,
            credential,
            new KeyVault.KeyClientOptions { Transport = new HttpClientTransport(httpClient) });
    }

    // Use explicit service-principal credentials from configuration when all three are set; otherwise fall back to
    // DefaultAzureCredential, which covers a managed identity, an Azure CLI sign-in, or the AZURE_* environment
    // variables. Production on Azure uses a managed identity and needs none of these set.
    /// <remarks>
    /// Internal rather than private so the key ring authenticates with the very same chain: the ring is not a
    /// second identity to configure, it is reached by whatever already reaches the vault.
    /// </remarks>
    internal static TokenCredential BuildCredential(AzureKeyVaultOptions settings)
        => !string.IsNullOrWhiteSpace(settings.TenantId)
                && !string.IsNullOrWhiteSpace(settings.ClientId)
                && !string.IsNullOrWhiteSpace(settings.ClientSecret)
            ? new ClientSecretCredential(settings.TenantId, settings.ClientId, settings.ClientSecret)
            : new DefaultAzureCredential();

    /// <summary>
    /// Signs the JWS signing input with a Key Vault key under the given JWS algorithm. Key Vault hashes the data
    /// and returns the raw signature already in JWS wire format (R||S for EC).
    /// </summary>
    public async Task<byte[]> SignAsync(string keyId, string algorithm, byte[] data, CancellationToken cancellationToken)
    {
        var client = GetCryptographyClient(keyId);
        var result = await client.SignDataAsync(MapSignatureAlgorithm(algorithm), data, cancellationToken);
        return result.Signature;
    }

    private static SignatureAlgorithm MapSignatureAlgorithm(string algorithm) => algorithm switch
    {
        SigningAlgorithms.RS256 => SignatureAlgorithm.RS256,
        SigningAlgorithms.RS384 => SignatureAlgorithm.RS384,
        SigningAlgorithms.RS512 => SignatureAlgorithm.RS512,

        SigningAlgorithms.PS256 => SignatureAlgorithm.PS256,
        SigningAlgorithms.PS384 => SignatureAlgorithm.PS384,
        SigningAlgorithms.PS512 => SignatureAlgorithm.PS512,

        SigningAlgorithms.ES256 => SignatureAlgorithm.ES256,
        SigningAlgorithms.ES384 => SignatureAlgorithm.ES384,
        SigningAlgorithms.ES512 => SignatureAlgorithm.ES512,

        _ => throw new NotSupportedException($"The Azure Key Vault store does not sign '{algorithm}'."),
    };

    /// <summary>
    /// Unwraps (decrypts) a CEK with a Key Vault RSA key under the given key-management algorithm (RSA-OAEP-256,
    /// RSA-OAEP or RSA1_5). Key Vault decrypts a raw JWE ciphertext directly. Returns null when the vault rejects
    /// the ciphertext, so a wrong key or tampered ciphertext is indistinguishable, which the seam's padding-oracle
    /// mitigation relies on. The JWE header is unused: an RSA unwrap needs only the ciphertext.
    /// </summary>
    public async Task<byte[]?> UnwrapKeyAsync(
        string keyId, string algorithm, JsonWebTokenHeader header, byte[] encryptedKey, CancellationToken cancellationToken)
    {
        var encryptionAlgorithm = MapEncryptionAlgorithm(algorithm);
        try
        {
            var client = GetCryptographyClient(keyId);
            var result = await client.DecryptAsync(encryptionAlgorithm, encryptedKey, cancellationToken);
            return result.Plaintext;
        }
        catch (RequestFailedException failure) when (failure.Status == (int)HttpStatusCode.BadRequest)
        {
            // Only a rejected ciphertext becomes null, and only because the seam requires it: null is the contract's
            // way of saying "this did not decrypt", which keeps a wrong key indistinguishable from bad padding.
            // Everything else must throw. A 429 (Key Vault throttles per vault, and this key is on the token path),
            // a 403 (the identity lost its Crypto User role), a 5xx: none of those are decryption failures, and
            // reporting them as one would tell the caller its client sent a bad JWE while the real fault is ours.
            return null;
        }
    }

    private static EncryptionAlgorithm MapEncryptionAlgorithm(string algorithm) => algorithm switch
    {
        EncryptionAlgorithms.KeyManagement.RsaOaep256 => EncryptionAlgorithm.RsaOaep256,
        EncryptionAlgorithms.KeyManagement.RsaOaep => EncryptionAlgorithm.RsaOaep,
        EncryptionAlgorithms.KeyManagement.Rsa1_5 => EncryptionAlgorithm.Rsa15,
        _ => throw new NotSupportedException($"The Azure Key Vault store does not unwrap '{algorithm}'."),
    };

    /// <summary>
    /// Derives the ECDH-ES shared secret. Azure Key Vault exposes no key-agreement primitive, so this store does
    /// not support ECDH-ES; a store built on AWS KMS (DeriveSharedSecret) or a PKCS#11 HSM (CKM_ECDH1_DERIVE) can.
    /// </summary>
    public Task<byte[]> AgreeKeyAsync(
        string keyId, string algorithm, JsonWebKey ephemeralPublicKey, CancellationToken cancellationToken)
        => throw new NotSupportedException(
            "Azure Key Vault exposes no ECDH key-agreement primitive; ECDH-ES is not supported by this store.");

    /// <summary>
    /// Enumerates every enabled version of the Key Vault key as a public-only JWK (RSA or EC, per the key type),
    /// each carrying the version-specific <c>kid</c> (<c>&lt;name&gt;/&lt;version&gt;</c>) and the version's
    /// creation time. Key Vault lists version metadata but not the public key, so each version's key is fetched.
    /// Called at publication time, so JWKS publishing and signature verification run locally against the result
    /// and never touch the vault on the hot path. The versioned <c>kid</c> is a Key Vault key identifier, which
    /// the crypto client turns straight back into a versioned URI for sign/unwrap, so no separate handle mapping
    /// is needed.
    /// </summary>
    public async IAsyncEnumerable<KeyVersion> GetKeyVersionsAsync(
        string keyName, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var properties in _keyClient.GetPropertiesOfKeyVersionsAsync(keyName, cancellationToken))
        {
            // A disabled version (rotated out, or not yet enabled) must not be published or produced with.
            if (properties.Enabled != true)
                continue;

            // A creation time is not decoration: it decides which version signs and when a rotation takes over.
            // Substituting a default would date the version to year one, so it could never be chosen to produce
            // with and would read as long past its propagation window. A version whose age is unknown cannot be
            // ordered, so it fails loud rather than sorting wrong, which is what the Vault client does too.
            var createdAt = properties.CreatedOn
                ?? throw new InvalidOperationException(
                    $"Key Vault reported no creation time for '{keyName}/{properties.Version}', so its place in " +
                    "the rotation cannot be determined.");

            var key = await _keyClient.GetKeyAsync(keyName, properties.Version, cancellationToken);
            var publicKey = ImportPublicKey(key.Value.Key) with { KeyId = $"{keyName}/{properties.Version}" };
            yield return new KeyVersion(publicKey, createdAt);
        }
    }

    // Imports a Key Vault public key into a public-only JWK of the matching type.
    private static JsonWebKey ImportPublicKey(KeyVault.JsonWebKey webKey)
    {
        if (webKey.KeyType == KeyVault.KeyType.Ec || webKey.KeyType == KeyVault.KeyType.EcHsm)
        {
            using var ecdsa = webKey.ToECDsa();
            return new EllipticCurveJsonWebKey().Apply(ecdsa.ExportParameters(false));
        }

        if (webKey.KeyType == KeyVault.KeyType.Rsa || webKey.KeyType == KeyVault.KeyType.RsaHsm)
        {
            using var rsa = webKey.ToRSA();
            return new RsaJsonWebKey().Apply(rsa.ExportParameters(false));
        }

        throw new NotSupportedException($"The Azure Key Vault store does not publish key type '{webKey.KeyType}'.");
    }

    /// <summary>
    /// The crypto client for a key version, cached because building one costs a metadata resolve on first use.
    /// </summary>
    /// <param name="keyId">The published <c>kid</c>: the key name and its version, as this client stamped it.</param>
    /// <remarks>
    /// The SDK builds the client from the parent <see cref="KeyVault.KeyClient"/>, which hands down its own
    /// credential, options and pipeline - so the injected transport carries through without being restated, and
    /// the key's URI is composed by the SDK rather than by string concatenation here.
    /// </remarks>
    private CryptographyClient GetCryptographyClient(string keyId)
        => _cryptographyClients.GetOrAdd(
            keyId,
            id =>
            {
                var (name, version) = ParseKeyId(id);
                return _keyClient.GetCryptographyClient(name, version);
            });

    /// <summary>
    /// Splits a published <c>kid</c> back into the name and version the SDK addresses a key by.
    /// </summary>
    /// <remarks>
    /// The kid is minted as <c>name/version</c> when the versions are published, and a Key Vault key name cannot
    /// contain a slash, so the split is unambiguous. A kid without a version is not one this client published.
    /// </remarks>
    private static (string Name, string Version) ParseKeyId(string keyId)
    {
        var separator = keyId.IndexOf('/');
        if (separator <= 0 || separator == keyId.Length - 1)
        {
            throw new InvalidOperationException(
                $"Malformed external key id '{keyId}': expected '<name>/<version>', which is what this client " +
                "publishes as the kid of each key version.");
        }

        return (keyId[..separator], keyId[(separator + 1)..]);
    }
}
