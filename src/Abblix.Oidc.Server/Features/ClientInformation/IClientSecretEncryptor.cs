// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Encrypts the client secret a tenant issues on dynamic registration and decrypts it again, so the client
/// configuration endpoint can return it when the client reads its registration (RFC 7592 section 3: the server "MUST
/// return all registered metadata about this client", and Appendix A.1: "The client's current registration access
/// token and client credentials (if applicable) MUST be included in the client information response").
/// </summary>
/// <remarks>
/// Each tenant encrypts with the key of its own <see cref="TenantDefinition.ClientSecretEncryption"/>, and the value is
/// bound to the tenant and the client, so it decrypts for no other client and in no other tenant. A tenant without
/// the key encrypts nothing.
/// </remarks>
public interface IClientSecretEncryptor
{
    /// <summary>
    /// <paramref name="secret"/>, issued to the client <paramref name="clientId"/> of <paramref name="tenant"/>,
    /// encrypted for that client, or null when the tenant has no key to encrypt it with.
    /// </summary>
    /// <param name="tenant">The tenant the client is registered at.</param>
    /// <param name="clientId">The client the secret is issued to.</param>
    /// <param name="secret">The secret issued.</param>
    byte[]? Encrypt(TenantDefinition tenant, string clientId, [Credential] string secret);

    /// <summary>
    /// The secret <paramref name="encryptedSecret"/> holds for the client <paramref name="clientId"/> of
    /// <paramref name="tenant"/>, or null when it does not decrypt there: the tenant has no key, has replaced the one it
    /// was encrypted with, or the value was encrypted for another client.
    /// </summary>
    /// <param name="tenant">The tenant the client is registered at.</param>
    /// <param name="clientId">The client the secret was issued to.</param>
    /// <param name="encryptedSecret">The value <see cref="Encrypt"/> returned.</param>
    string? Decrypt(TenantDefinition tenant, string clientId, byte[] encryptedSecret);
}
