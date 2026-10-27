// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// A <c>Startup</c> class, as a host built without the minimal hosting model declares its services and pipeline.
/// </summary>
/// <param name="configureServices">Registers the host's services.</param>
/// <param name="configure">Configures the host's pipeline.</param>
internal sealed class DelegatingStartup(Action<IServiceCollection> configureServices, Action<IApplicationBuilder> configure)
{
    /// <summary>
    /// Registers the host's services.
    /// </summary>
    public void ConfigureServices(IServiceCollection services) => configureServices(services);

    /// <summary>
    /// Configures the host's pipeline.
    /// </summary>
    public void Configure(IApplicationBuilder app) => configure(app);
}
