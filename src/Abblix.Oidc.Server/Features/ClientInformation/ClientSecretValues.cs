// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The client secrets whose values the server reads itself rather than only compares by hash: the key a
/// client_secret_jwt assertion is verified with (OpenID Connect Core 1.0 section 9), and the key a JWT is encrypted to
/// a client with (section 10.2).
/// </summary>
/// <remarks>
/// A secret the host declares carries its <see cref="ClientSecret.Value"/>. A client registered dynamically keeps its
/// secret encrypted alone (<see cref="ClientSecret.EncryptedValue"/>), and only a client_secret_jwt client has it
/// decrypted here, the one method that needs the value to authenticate; a registration stored with the value itself is
/// read as one the host declares.
/// </remarks>
internal static class ClientSecretValues
{
    /// <summary>
    /// Whether the secret of a client registered with <paramref name="tokenEndpointAuthMethod"/> is read back from its
    /// encrypted copy: client_secret_jwt alone, since verifying the client's HMAC-signed assertion needs it; every other
    /// method is verified against the hash.
    /// </summary>
    /// <param name="tokenEndpointAuthMethod">The client's authentication method.</param>
    public static bool AreReadFor(string tokenEndpointAuthMethod)
        => tokenEndpointAuthMethod == ClientAuthenticationMethods.ClientSecretJwt;

    /// <summary>
    /// Whether <paramref name="secret"/> keeps a form of its value <see cref="Of"/> reads for a client registered with
    /// <paramref name="tokenEndpointAuthMethod"/>: the value itself, or the encrypted copy where it is read back.
    /// </summary>
    /// <param name="tokenEndpointAuthMethod">The client's authentication method.</param>
    /// <param name="secret">The secret.</param>
    public static bool AreKeptIn(string tokenEndpointAuthMethod, ClientSecret secret)
        => secret.Value is { Length: > 0 } || (AreReadFor(tokenEndpointAuthMethod) && secret.EncryptedValue is not null);

    /// <summary>
    /// The values of <paramref name="client"/>'s secrets not expired at <paramref name="now"/>, the one expiring last
    /// first and one that never expires before any other, as a client rotating its secret holds the newer one.
    /// </summary>
    /// <param name="tenant">The tenant the client is registered at, whose key decrypts its secrets.</param>
    /// <param name="client">The client.</param>
    /// <param name="now">The time a secret's expiry is judged against.</param>
    /// <param name="encryptor">Decrypts a secret kept encrypted.</param>
    public static IEnumerable<string> Of(
        TenantDefinition tenant, ClientInfo client, DateTimeOffset now, IClientSecretEncryptor encryptor)
        => (client.ClientSecrets ?? [])
            .Where(secret => !(secret.ExpiresAt < now))
            .OrderByDescending(secret => secret.ExpiresAt ?? DateTimeOffset.MaxValue)
            .Select(secret => ValueOf(tenant, client, secret, encryptor))
            .OfType<string>();

    private static string? ValueOf(
        TenantDefinition tenant, ClientInfo client, ClientSecret secret, IClientSecretEncryptor encryptor)
    {
        if (secret.Value is { Length: > 0 } value)
            return value;

        if (AreReadFor(client.TokenEndpointAuthMethod) && secret.EncryptedValue is { } encrypted)
        {
            return encryptor.Decrypt(tenant, client.ClientId, encrypted);
        }

        return null;
    }
}
