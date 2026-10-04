// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
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
/// The key is the tenant's first signing key, as for the other tokens the server signs, and the signing itself is
/// the default signer's, which refuses a key whose algorithm the deployment does not allow
/// (<see cref="SecurityEventsOptions.AllowedSigningAlgorithms"/>). A host transmitting security events under
/// multi-tenancy registers this signer in place of the one <c>AddSecurityEvents</c> registers; startup refuses any
/// other.
/// </remarks>
/// <param name="keys">The signing keys of the tenant serving the request.</param>
/// <param name="creator">The JWT core's token creator.</param>
/// <param name="options">What the deployment allows to sign with.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantSecurityEventTokenSigner(
    IAuthServiceKeysProvider keys,
    IJsonWebTokenCreator creator,
    IOptions<SecurityEventsOptions> options) : ISecurityEventTokenSigner
{
    /// <inheritdoc />
    public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
        => new DefaultSecurityEventTokenSigner(
                creator,
                SigningKeyAsync,
                options.Value.AllowedSigningAlgorithms ?? [.. SecurityEventsOptions.DefaultSigningAlgorithms])
            .SignAsync(token, cancellationToken);

    /// <exception cref="InvalidOperationException">The tenant has no signing key.</exception>
    private async Task<JsonWebKey> SigningKeyAsync(CancellationToken cancellationToken)
        => await keys.GetSigningKeys(true).FirstOrDefaultAsync(cancellationToken)
           ?? throw new InvalidOperationException(
               "A security event token cannot be signed: the tenant serving the request has no signing key.");
}
