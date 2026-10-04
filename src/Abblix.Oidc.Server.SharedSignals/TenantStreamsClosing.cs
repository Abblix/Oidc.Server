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

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Deletes the streams a released tenant's receivers created, and the events queued on them.
/// </summary>
/// <remarks>
/// Runs inside the released tenant, in the creation that was served, so it reaches that creation's streams and no
/// other's: a tenant created again under the same id keeps its own. The stores are resolved when a tenant is closed
/// rather than when the catalog of tenants is built, since signing a tenant's events depends on that catalog.
/// </remarks>
/// <param name="serviceProvider">Resolves the stream store and the management of streams.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantStreamsClosing(IServiceProvider serviceProvider) : ITenantClosing
{
    /// <inheritdoc />
    public async Task CloseAsync(TenantDefinition tenant, CancellationToken cancellationToken)
    {
        var streams = serviceProvider.GetRequiredService<IStreamStore>();
        var management = serviceProvider.GetRequiredService<StreamManagementService>();

        using var scope = TenantScope.Enter(tenant);
        foreach (var stream in await streams.ListAllAsync(cancellationToken))
            await management.DeleteStreamAsync(stream.ReceiverId, stream.StreamId, cancellationToken);
    }
}
