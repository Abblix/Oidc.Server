// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.Extensions.DependencyInjection;
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
/// accessor is in use, and a host running no web server, such as a worker sharing the web application's
/// registration, has no pipeline to call it in. A server whose options declare one tenant at an issuer without a
/// path serves it without the call (<see cref="LoneTenant"/>), and the refusal names why any other needs it.
/// </remarks>
/// <param name="accessor">Tells the tenant of a request.</param>
/// <param name="call">Records whether the pipeline calls <see cref="MultiTenancyExtensions.UseMultiTenancy"/>.</param>
/// <param name="lone">Tells whether the one tenant is served without the call, and why the call is needed if not.</param>
/// <param name="services">Tells whether the host runs a web server.</param>
internal sealed class MultiTenancyCallCheck(
    ITenantAccessor accessor,
    MultiTenancyCall call,
    LoneTenant lone,
    IServiceProvider services) : IHostedLifecycleService
{
    /// <inheritdoc />
    public Task StartingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public Task StartedAsync(CancellationToken cancellationToken)
    {
        if (services.GetService<IServer>() is not null &&
            accessor is HttpContextTenantAccessor &&
            !call.Made &&
            lone.WhyTheCallIsNeeded is { } why)
        {
            throw new InvalidOperationException(
                $"The pipeline does not call {nameof(MultiTenancyExtensions.UseMultiTenancy)}(), which this server " +
                $"needs because {why}: without it no request reaches a tenant and every endpoint of the server " +
                $"answers 404. Call {nameof(MultiTenancyExtensions.UseMultiTenancy)}() before UseRouting() and " +
                "UseAuthentication().");
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
