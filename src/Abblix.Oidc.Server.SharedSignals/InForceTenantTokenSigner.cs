// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Signs a tenant's security event tokens with the keys of its definition in force when each token is signed, so a
/// key the tenant rotates in signs from then on, a token queued before the rotation included.
/// </summary>
/// <param name="signer">Signs with a given tenant's keys.</param>
/// <param name="current">The tenant's definition in force.</param>
/// <param name="guard">Refuses to sign where the tenant is not served.</param>
internal sealed class InForceTenantTokenSigner(
    TenantSecurityEventTokenSigner signer,
    Func<TenantDefinition> current,
    TenantPartGuard guard) : ISecurityEventTokenSigner
{
    /// <inheritdoc />
    public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
    {
        guard.EnsureServed();
        return signer.SignAsync(current(), token, cancellationToken);
    }
}
