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
/// The key is the tenant's first signing key that performs an algorithm <see cref="AlgorithmsFor"/> names: one the
/// deployment allows (<see cref="SecurityEventsOptions.AllowedSigningAlgorithms"/>) and the tenant's security profile
/// permits, or, where the deployment sets no allowlist, one the profile admits in place of the RS256 that stands for:
/// FAPI 1.0 Part 2 section 8.6, "For JWS, both clients and authorization servers shall use PS256 or ES256 algorithms",
/// and FAPI 2.0 section 5.4.1, "Authorization servers, clients, and resource servers when creating or processing JWTs
/// shall ... use PS256, ES256, or EdDSA (using the Ed25519 variant) algorithms". The profile is the tenant's own: a
/// stream names its receiver by the identifier its credentials carry, not by a client of the tenant, so no client's
/// profile is in force for what it is sent. Where no key qualifies the token is not signed at all, so a tenant held to
/// a profile never sends one under an algorithm the profile refuses. A host transmitting security events registers
/// this signer in place of the one <c>AddSecurityEvents</c> registers; startup refuses any other.
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
    /// <exception cref="InvalidOperationException">No signing key of the tenant performs an algorithm both the
    /// deployment allows and its profile permits.</exception>
    internal async Task<string> SignAsync(
        TenantDefinition tenant,
        SecurityEventToken token,
        CancellationToken cancellationToken)
    {
        var profile = SecurityProfileRequirements.For(tenant, null);
        var permitted = AlgorithmsFor(profile, options.Value);

        await foreach (var key in keys.GetSigningKeys(tenant, true).WithCancellation(cancellationToken))
        {
            if (AlgorithmOf(key, permitted) is not { } algorithm)
                continue;

            // Written into the header so the profile judges what the token is signed with, and so a key declaring no
            // algorithm signs with the one chosen for it
            token.Token.Header.Algorithm = algorithm;
            return await issuer.IssueAsync(profile, token.Token, key);
        }

        throw new InvalidOperationException(
            $"A security event token cannot be signed: no signing key of the tenant '{tenant.Id}' performs an " +
            "algorithm both the deployment allows and the tenant's security profile permits " +
            $"({(permitted.Length > 0 ? string.Join(", ", permitted) : "none")}).");
    }

    /// <summary>
    /// The algorithms a tenant held to <paramref name="profile"/> signs a security event token with: those the
    /// deployment allows that the profile permits, or, where the deployment sets no allowlist, those the profile
    /// admits, the default RS256 where it admits any.
    /// </summary>
    /// <remarks>
    /// The default stands for no choice of the deployment's, so a profile that refuses it is not overruled by it. It
    /// stays the set the deployment's verifier accepts: what this server signs does not widen what it accepts.
    /// </remarks>
    /// <param name="profile">The tenant's security profile.</param>
    /// <param name="options">What the deployment allows to sign with.</param>
    internal static string[] AlgorithmsFor(SecurityProfileRequirements profile, SecurityEventsOptions options)
        => options.AllowedSigningAlgorithms is { } allowed
            ? [.. allowed.Where(profile.PermitsSigningAlgorithm)]
            : [.. (IEnumerable<string>?)profile.SigningAlgorithmsAdmitted()
                  ?? SecurityEventsOptions.DefaultSigningAlgorithms];

    /// <summary>
    /// The first of <paramref name="algorithms"/> <paramref name="key"/> signs with, or null where it signs with none:
    /// the one it declares, or, for a key declaring none, as one taken from a certificate, the first its material
    /// performs.
    /// </summary>
    internal static string? AlgorithmOf(JsonWebKey key, string[] algorithms)
        => algorithms.FirstOrDefault(key.CanPerform);
}
