// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.AspNetCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using MinimalApiRegistration = Abblix.Oidc.Server.MinimalApi.ServiceCollectionExtensions;
using MvcRegistration = Abblix.Oidc.Server.Mvc.ServiceCollectionExtensions;

namespace Abblix.Oidc.Server.UnitTests.Features.DependencyInjection;

/// <summary>
/// The real registration of each transport adapter leaves what the other adapter's conflict check finds, so the
/// second adapter is refused in either order; one adapter alone is never refused.
/// </summary>
/// <remarks>
/// The conflict check is asked directly rather than through the second adapter's registration, since that
/// registration refuses the first adapter's formatters on other grounds as well, which would hide a missing mark.
/// </remarks>
public class TransportAdapterRegistrationTests
{
    private const string Message = "Both adapters are registered.";

    [Fact]
    public void TheMinimalApiAdapterRegistration_IsFoundByTheMvcAdapterCheck()
    {
        var services = new ServiceCollection();
        MinimalApiRegistration.AddOidcMinimalApi(services);

        Assert.Throws<InvalidOperationException>(() => TransportAdapterConflict.ThrowIfRegistered(
            services, TransportAdapterConflict.MinimalApiAdapterAssemblyName, Message));
    }

    [Fact]
    public void TheMvcAdapterRegistration_IsFoundByTheMinimalApiAdapterCheck()
    {
        var services = new ServiceCollection();
        MvcRegistration.AddOidcMvc(services);

        Assert.Throws<InvalidOperationException>(() => TransportAdapterConflict.ThrowIfRegistered(
            services, TransportAdapterConflict.MvcAdapterAssemblyName, Message));
    }

    [Fact]
    public void EachAdapterAlone_IsRegistered()
    {
        Assert.Null(Record.Exception(() => MvcRegistration.AddOidcMvc(new ServiceCollection())));
        Assert.Null(Record.Exception(() => MinimalApiRegistration.AddOidcMinimalApi(new ServiceCollection())));
    }
}
