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
/// Each stream is deleted on its own, so one that fails is logged, the others are still deleted and the tenant is
/// reported not closed; once the token is canceled, the streams and tenants not reached are left and reported. The
/// store and the management of streams are resolved when a tenant is closed rather than when the catalog of tenants
/// is built: signing a tenant's events depends on that catalog, and a store of declared streams cannot be built
/// outside a tenant, which would hide the startup check that refuses it.
/// </remarks>
/// <param name="logger">Records a stream that could not be deleted.</param>
/// <param name="serviceProvider">Resolves the stream store and the management of streams.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed partial class TenantStreamsClosing(
    ILogger<TenantStreamsClosing> logger,
    IServiceProvider serviceProvider) : ITenantClosing
{
    /// <inheritdoc />
    public async Task<IReadOnlyDictionary<TenantDefinition, Exception>> CloseAsync(
        IReadOnlyCollection<TenantDefinition> tenants,
        CancellationToken cancellationToken)
    {
        var streams = serviceProvider.GetRequiredService<IStreamStore>();
        var management = serviceProvider.GetRequiredService<StreamManagementService>();

        var failures = new Dictionary<TenantDefinition, Exception>();
        foreach (var tenant in tenants)
        {
            // Stopped, the tenants not reached yet are not closed, and asking the store for them would not end sooner
            if (cancellationToken.IsCancellationRequested)
            {
                failures[tenant] = new OperationCanceledException(cancellationToken);
                continue;
            }

            try
            {
                if (await FailureOfAsync(tenant, streams, management, cancellationToken) is { } failure)
                    failures[tenant] = failure;
            }
            catch (Exception exception)
            {
                failures[tenant] = exception;
            }
        }

        return failures;
    }

    /// <summary>
    /// Deletes every stream of <paramref name="tenant"/>, each on its own, and gives the first failure, or null when
    /// all were deleted.
    /// </summary>
    private async Task<Exception?> FailureOfAsync(
        TenantDefinition tenant,
        IStreamStore streams,
        StreamManagementService management,
        CancellationToken cancellationToken)
    {
        using var scope = TenantScope.Enter(tenant);
        Exception? first = null;
        foreach (var stream in await streams.ListAllAsync(cancellationToken))
        {
            try
            {
                await management.DeleteStreamAsync(stream.ReceiverId, stream.StreamId, cancellationToken);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                LogStreamNotDeleted(exception, stream.StreamId, tenant.Id);
                first ??= exception;
            }
        }

        return first;
    }
}
