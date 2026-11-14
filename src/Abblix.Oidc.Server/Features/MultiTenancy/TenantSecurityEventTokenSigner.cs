// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Infrastructure;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Signs a security event token with a signing key of the tenant serving the request, so a receiver verifies what a
/// tenant transmits with that tenant's published keys alone.
/// </summary>
/// <remarks>
/// The key is the tenant's first signing key of an algorithm the deployment allows
/// (<see cref="SecurityEventsOptions.AllowedSigningAlgorithms"/>) and the tenant's security profile permits: FAPI 1.0
/// Part 2 section 8.6, "For JWS, both clients and authorization servers shall use PS256 or ES256 algorithms", and FAPI
/// 2.0 section 5.4.1, "Authorization servers, clients, and resource servers when creating or processing JWTs shall ...
/// use PS256, ES256, or EdDSA (using the Ed25519 variant) algorithms". The profile is the tenant's own: a stream names
/// its receiver by the identifier its credentials carry, not by a client of the tenant, so no client's profile is in
/// force for what it is sent. Where no key qualifies the token is not signed at all, so a tenant held to a profile
/// never sends one under an algorithm the profile refuses. A host transmitting security events registers this signer
/// in place of the one <c>AddSecurityEvents</c> registers; startup refuses any other.
/// </remarks>
/// <param name="keys">The signing keys of the tenant serving the request.</param>
/// <param name="issuer">Signs the token once the tenant's profile admits its algorithm.</param>
/// <param name="options">What the deployment allows to sign with.</param>
/// <param name="tenantAccessor">Names the tenant the request is served at.</param>
public sealed class TenantSecurityEventTokenSigner(
    IAuthServiceKeysProvider keys,
    ProfiledJwtIssuer issuer,
    IOptions<SecurityEventsOptions> options,
    ITenantAccessor tenantAccessor) : ISecurityEventTokenSigner
{
    /// <inheritdoc />
    public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
        => SignAsync(tenantAccessor.CurrentTenant(), token, cancellationToken);

    /// <summary>
    /// Signs <paramref name="token"/> with a signing key of <paramref name="tenant"/>, as the Shared Signals
    /// transmitter built for that tenant does.
    /// </summary>
    /// <param name="tenant">The tenant whose key signs the token.</param>
    /// <param name="token">The token to sign.</param>
    /// <param name="cancellationToken">Cancels reading the tenant's keys.</param>
    /// <exception cref="InvalidOperationException">The tenant has no signing key of an algorithm both the deployment
    /// allows and its profile permits.</exception>
    internal async Task<string> SignAsync(
        TenantDefinition tenant,
        SecurityEventToken token,
        CancellationToken cancellationToken)
    {
        var profile = SecurityProfileRequirements.For(tenant, null);
        var permitted = (options.Value.AllowedSigningAlgorithms ?? [.. SecurityEventsOptions.DefaultSigningAlgorithms])
            .Where(profile.PermitsSigningAlgorithm)
            .ToArray();

        var signingKey = await keys.GetSigningKeys(tenant, true).FirstOrDefaultAsync(
                             key => key.Algorithm is { } algorithm &&
                                    permitted.Contains(algorithm, StringComparer.Ordinal),
                             cancellationToken)
                         ?? throw new InvalidOperationException(
                             $"A security event token cannot be signed: the tenant '{tenant.Id}' has no signing key " +
                             "of an algorithm both the deployment allows and the tenant's security profile permits " +
                             $"({(permitted.Length > 0 ? string.Join(", ", permitted) : "none")}).");

        // The algorithm follows the key, written into the header so the profile judges what the token is signed with
        token.Token.Header.Algorithm = signingKey.Algorithm;
        return await issuer.IssueAsync(profile, token.Token, signingKey);
    }
}
