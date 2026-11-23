// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;
using Abblix.Jwt.Encryption;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Encrypts the client secrets of one tenant with the key of its <see cref="ClientSecretEncryptionSettings"/>, by the
/// deterministic authenticated encryption pairwise subject identifiers are sealed with, bound to the tenant and the
/// client as associated data.
/// </summary>
/// <remarks>
/// Deterministic encryption reveals only that two values are equal, and every secret this server issues is random,
/// so no two clients hold equal ones.
/// </remarks>
internal sealed class ClientSecretEncryptor
{
    private readonly DeterministicAeadEncryptor? _encryptor;

    /// <summary>
    /// Creates the encryptor of a tenant, which decrypts nothing when <paramref name="settings"/> is null.
    /// </summary>
    /// <param name="settings">The tenant's key, or null when it has none.</param>
    /// <exception cref="ArgumentException">The settings carry a key or name a hash the encryption cannot use, which
    /// the check of the tenant list refuses before the tenant is served.</exception>
    public ClientSecretEncryptor(ClientSecretEncryptionSettings? settings)
    {
        if (settings is null)
            return;

        if (ClientSecretEncryptionSettings.Refusals(settings).FirstOrDefault() is { } refusal)
            throw new ArgumentException(refusal, nameof(settings));

        var hashAlgorithm = DeterministicSealKey.HashAlgorithmNamed(settings.HashAlgorithm) ??
            throw new ArgumentException(settings.HashAlgorithm, nameof(settings));

        _encryptor = new DeterministicAeadEncryptor(hashAlgorithm, Convert.FromBase64String(settings.Key));
    }

    /// <inheritdoc cref="IClientSecretEncryptor.Encrypt"/>
    public byte[] Encrypt(TenantDefinition tenant, string clientId, [Credential] string secret)
    {
        var encryptor = _encryptor ?? throw new InvalidOperationException(
            $"The tenant '{tenant.Id}' has no {nameof(TenantDefinition.ClientSecretEncryption)}, which the check of " +
            "the tenant list requires of every tenant while the server serves dynamic client registration");

        return encryptor.Seal(Encoding.UTF8.GetBytes(secret), AssociatedData(tenant, clientId));
    }

    /// <inheritdoc cref="IClientSecretEncryptor.Decrypt"/>
    public string? Decrypt(TenantDefinition tenant, string clientId, byte[] encryptedSecret)
        => _encryptor?.Open(encryptedSecret, AssociatedData(tenant, clientId)) is { } secret
            ? Encoding.UTF8.GetString(secret)
            : null;

    /// <summary>
    /// The tenant and the client a secret is bound to, named as the tenant's stored data is, so a value encrypted for
    /// one client of one creation of a tenant decrypts for no other.
    /// </summary>
    private static byte[] AssociatedData(TenantDefinition tenant, string clientId)
        => Encoding.UTF8.GetBytes(TenantKey.Of(tenant, $"client_secret:{clientId}"));
}
