// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.Hosting;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// Stops a host from starting when its pipeline lacks <see cref="MultiTenancyExtensions.UseMultiTenancy"/>, which
/// would otherwise let no request reach a tenant, so the server's endpoints serve none.
/// </summary>
/// <remarks>
/// It runs once the host has started, when the pipeline is built under the minimal hosting model and under a
/// <c>Startup</c> class alike, and adds nothing to the pipeline. A host that registers its own
/// <see cref="ITenantAccessor"/> finds the tenant its own way, so the call is required only while the server's own
/// accessor is in use.
/// </remarks>
/// <param name="accessor">Tells the tenant of a request.</param>
/// <param name="call">Records whether the pipeline calls <see cref="MultiTenancyExtensions.UseMultiTenancy"/>.</param>
internal sealed class MultiTenancyCallCheck(ITenantAccessor accessor, MultiTenancyCall call) : IHostedLifecycleService
{
    /// <inheritdoc />
    public Task StartingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public Task StartedAsync(CancellationToken cancellationToken)
    {
        if (accessor is HttpContextTenantAccessor && !call.Made)
        {
            throw new InvalidOperationException(
                $"The pipeline does not call {nameof(MultiTenancyExtensions.UseMultiTenancy)}(), so no request reaches " +
                "a tenant and every endpoint of the server answers 404. Call " +
                $"{nameof(MultiTenancyExtensions.UseMultiTenancy)}() before UseRouting() and UseAuthentication().");
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
