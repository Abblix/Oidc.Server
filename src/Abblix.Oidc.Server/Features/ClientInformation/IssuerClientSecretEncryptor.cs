// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Encrypts client secrets with the key of the tenant they are issued at, keeping one
/// <see cref="ClientSecretEncryptor"/> for each tenant.
/// </summary>
/// <param name="logger">Records a secret that no longer decrypts.</param>
/// <param name="encryptors">The encryptor of each tenant.</param>
internal sealed partial class IssuerClientSecretEncryptor(
    ILogger<IssuerClientSecretEncryptor> logger,
    IIssuerLocal<ClientSecretEncryptor> encryptors) : IClientSecretEncryptor
{
    private ClientSecretEncryptor EncryptorOf(TenantDefinition tenant)
    {
        var settings = tenant.ClientSecretEncryption;
        return encryptors.GetOrCreate(tenant, settings, () => new ClientSecretEncryptor(settings));
    }

    /// <inheritdoc />
    public byte[] Encrypt(TenantDefinition tenant, string clientId, [Credential] string secret)
        => EncryptorOf(tenant).Encrypt(tenant, clientId, secret);

    /// <inheritdoc />
    public string? Decrypt(TenantDefinition tenant, string clientId, byte[] encryptedSecret)
    {
        var secret = EncryptorOf(tenant).Decrypt(tenant, clientId, encryptedSecret);
        if (secret is null)
            LogSecretNotDecrypted(clientId, tenant.Id);

        return secret;
    }
}
