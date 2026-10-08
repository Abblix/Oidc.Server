// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Deletes the streams a released tenant's receivers created, and the events queued on them.
/// </summary>
/// <remarks>
/// Runs inside the released tenant, in the definition last served for that creation, so it reaches that creation's
/// streams in the store they were kept in and no other's: a tenant created again under the same id keeps its own.
/// Each stream is deleted on its own, so one that fails is logged and the others are still deleted. The store and the
/// management of streams are resolved when a tenant is closed rather than when the catalog of tenants is built: signing
/// a tenant's events depends on that catalog, and a store of declared streams cannot be built outside a tenant, which
/// would hide the startup check that refuses it.
/// </remarks>
/// <param name="logger">Records a stream that could not be deleted.</param>
/// <param name="serviceProvider">Resolves the stream store and the management of streams.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed partial class TenantStreamsClosing(
    ILogger<TenantStreamsClosing> logger,
    IServiceProvider serviceProvider) : ITenantClosing
{
    /// <inheritdoc />
    public async Task<IReadOnlyDictionary<string, Exception>> CloseAsync(
        IReadOnlyCollection<TenantDefinition> tenants,
        CancellationToken cancellationToken)
    {
        var streams = serviceProvider.GetRequiredService<IStreamStore>();
        var management = serviceProvider.GetRequiredService<StreamManagementService>();

        var failures = new Dictionary<string, Exception>(StringComparer.Ordinal);
        foreach (var tenant in tenants)
        {
            try
            {
                await CloseAsync(tenant, streams, management, cancellationToken);
            }
            catch (Exception exception)
            {
                failures[tenant.Id] = exception;
            }
        }

        return failures;
    }

    private async Task CloseAsync(
        TenantDefinition tenant,
        IStreamStore streams,
        StreamManagementService management,
        CancellationToken cancellationToken)
    {
        using var scope = TenantScope.Enter(tenant);
        foreach (var stream in await streams.ListAllAsync(cancellationToken))
        {
            try
            {
                await management.DeleteStreamAsync(stream.ReceiverId, stream.StreamId, cancellationToken);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                LogStreamNotDeleted(exception, stream.StreamId, tenant.Id);
            }
        }
    }
}
