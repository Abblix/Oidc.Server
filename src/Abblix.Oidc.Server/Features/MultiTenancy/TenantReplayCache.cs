// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt.ReplayPrevention;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Keeps the identifiers of each tenant's single-use tokens - client assertions, DPoP proofs, bearer grants - in a
/// space of its own.
/// </summary>
/// <remarks>
/// <para>
/// The identifier is chosen by the client, so two tenants' clients can present the same one, and without this
/// the first tenant to see it would refuse the other's genuine token as a replay.
/// </para>
/// <para>
/// A reservation made outside any tenant keeps to the shared space rather than being refused, unlike stored
/// entities: this cache is shared with the receivers of security event tokens a host may run beside the server,
/// which work outside any tenant, and every tenant's reservation lies in its own space, so the two never meet.
/// </para>
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantReplayCache(IReplayCache inner, ITenantAccessor tenantAccessor) : IReplayCache
{
    /// <inheritdoc />
    public Task<bool> TryReserveAsync(
        string identifier,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
        => inner.TryReserveAsync(Scope(identifier), expiresAt, cancellationToken);

    /// <inheritdoc />
    public Task ReleaseAsync(string identifier, CancellationToken cancellationToken = default)
        => inner.ReleaseAsync(Scope(identifier), cancellationToken);

    private string Scope(string identifier)
        => tenantAccessor.Current is null ? identifier : TenantKey.Of(tenantAccessor, identifier);
}
