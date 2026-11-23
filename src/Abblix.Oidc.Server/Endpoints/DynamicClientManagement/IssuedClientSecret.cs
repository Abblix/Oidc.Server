// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// The client secret a client information response carries for a registered client, and when it expires: the one
/// answer a read and an update of the registration give (RFC 7592 section 3 and Appendix A.1).
/// </summary>
internal static class IssuedClientSecret
{
    /// <summary>
    /// The secret issued to <paramref name="client"/>, decrypted, or null when none of its secrets was kept encrypted
    /// or none decrypts: one issued before the tenant had a client secret encryption key, or under a key it has since
    /// replaced, is answered without.
    /// </summary>
    /// <param name="tenant">The tenant the client is registered at.</param>
    /// <param name="client">The registered client.</param>
    /// <param name="encryptor">Decrypts the secret.</param>
    public static string? Of(TenantDefinition tenant, ClientInfo client, IClientSecretEncryptor encryptor)
    {
        // Of several, the one expiring last; one that never expires outlasts all
        return (client.ClientSecrets ?? [])
            .Where(secret => secret.EncryptedValue is not null)
            .OrderByDescending(secret => secret.ExpiresAt ?? DateTimeOffset.MaxValue)
            .Select(secret => encryptor.Decrypt(tenant, client.ClientId, secret.EncryptedValue!))
            .FirstOrDefault(secret => secret is not null);
    }

    /// <summary>
    /// The latest expiration time among the secrets of <paramref name="client"/>, or null when it holds none or none of
    /// them expires.
    /// </summary>
    /// <param name="client">The registered client.</param>
    public static DateTimeOffset? ExpiresAt(ClientInfo client)
    {
        if (client.ClientSecrets == null)
            return null;

        DateTimeOffset? result = null;
        foreach (var expiresAt in client.ClientSecrets.Select(secret => secret.ExpiresAt))
        {
            if (!expiresAt.HasValue)
                continue;

            if (!result.HasValue || result.Value < expiresAt.Value)
                result = expiresAt;
        }

        return result;
    }
}
