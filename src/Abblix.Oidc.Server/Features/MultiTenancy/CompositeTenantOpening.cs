// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The openings of one reading as one (Composite): each readies every tenant, and a tenant any of them fails is not
/// ready. They share one refresh period, so a custodian that does not answer delays the next reading by no more
/// than that; when it runs out, an opening reports what it readied by then, and every tenant of one that does not
/// counts as not ready.
/// </summary>
/// <param name="openings">The openings, in the order they run.</param>
/// <param name="options">The refresh period the openings share.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal sealed class CompositeTenantOpening(
    IEnumerable<ITenantOpening> openings,
    IOptions<MultiTenancyOptions> options) : ITenantOpening
{
    /// <inheritdoc />
    public Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
        IReadOnlyCollection<TenantDefinition> tenants,
        CancellationToken cancellationToken)
        => OpenAsync(tenants, true, cancellationToken);

    /// <summary>
    /// Readies <paramref name="tenants"/>, within one refresh period when <paramref name="limited"/>.
    /// </summary>
    /// <param name="tenants">The tenants about to be served for the first time.</param>
    /// <param name="limited">Whether the openings must finish within one refresh period; the tenants the settings
    /// declare are opened without a limit when the server starts, since the start waits for all of them.</param>
    /// <param name="cancellationToken">Cancels the openings.</param>
    public async Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
        IReadOnlyCollection<TenantDefinition> tenants,
        bool limited,
        CancellationToken cancellationToken)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (limited)
            limit.CancelAfter(options.Value.RefreshEvery);

        var failures = new Dictionary<string, Exception>(StringComparer.Ordinal);
        try
        {
            foreach (var opening in openings)
            {
                foreach (var (tenantId, exception) in await opening.OpenAsync(tenants, limit.Token))
                    failures.TryAdd(tenantId, exception);
            }

            // An opening may report a stop as failures of the tenants it did not reach; the caller's own stop is a
            // stop, not tenants that cannot be readied
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            foreach (var tenant in tenants)
                failures.TryAdd(tenant.Id, exception);
        }

        return failures;
    }
}
