// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;
using Abblix.Jwt;
using Abblix.Jwt.Signing;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// The keys a client signs a JWT with: those it publishes, or those its client secret derives.
/// </summary>
/// <param name="clientJwksProvider">Reads the keys the client publishes.</param>
/// <param name="secretEncryptor">Decrypts a client secret kept encrypted.</param>
/// <param name="clock">The time a secret's expiry is judged against.</param>
internal sealed class ClientSigningKeys(
    IClientKeysProvider clientJwksProvider,
    IClientSecretEncryptor secretEncryptor,
    TimeProvider clock)
{
    /// <summary>
    /// The algorithms a client secret signs with: the HS algorithms alone (OpenID Connect Core 1.0 section 9).
    /// </summary>
    public static IReadOnlySet<string> SecretAlgorithms => HmacAlgorithms.All;

    /// <summary>
    /// The keys of a JWT the client signed with its secret: one per unexpired secret and HS algorithm the secret's
    /// length keys (RFC 7518 section 3.2), the validator taking the one matching the token's alg.
    /// </summary>
    public IAsyncEnumerable<JsonWebKey> FromSecret(TenantDefinition tenant, ClientInfo client)
        => (
            from secret in ClientSecretValues.Of(tenant, client, clock.GetUtcNow(), secretEncryptor)
            let octets = Encoding.UTF8.GetBytes(secret)
            from algorithm in HmacAlgorithms.KeyedBy(octets.Length)
            select (JsonWebKey)new OctetJsonWebKey { Algorithm = algorithm, KeyValue = octets }
        ).ToAsyncEnumerable();

    /// <summary>
    /// The keys the client publishes, read only where its profile lets them be fetched.
    /// </summary>
    /// <remarks>
    /// FAPI 1.0 Part 2 section 8.9 "requires that jwks_uri endpoints shall be served over TLS". Held here, where the
    /// keys are read, so no path verifies with keys fetched in the clear, whatever schemes the host lets the fetcher
    /// use.
    /// </remarks>
    public IAsyncEnumerable<JsonWebKey> Published(TenantDefinition tenant, ClientInfo client, bool refetch)
    {
        if (SecurityProfileConsistency.FindJwksUriViolations(
                client.JwksUri,
                SecurityProfileRequirements.For(client, tenant.DefaultSecurityProfile)).Count > 0)
        {
            return AsyncEnumerable.Empty<JsonWebKey>();
        }

        return clientJwksProvider.GetSigningKeys(client, refetch);
    }
}
