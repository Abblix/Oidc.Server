// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using MinimalApiRegistration = Abblix.Oidc.Server.MinimalApi.ServiceCollectionExtensions;
using MvcRegistration = Abblix.Oidc.Server.Mvc.ServiceCollectionExtensions;

namespace Abblix.Oidc.Server.UnitTests.Features.DependencyInjection;

/// <summary>
/// The real registration of each transport adapter refuses to run after the other one's, in either order, since both
/// would then serve the same OIDC endpoints; one adapter alone is never refused.
/// </summary>
public class TransportAdapterRegistrationTests
{
    [Fact]
    public void TheMvcAdapterAddedAfterTheMinimalApiAdapter_IsRefused()
    {
        var services = new ServiceCollection();
        MinimalApiRegistration.AddOidcMinimalApi(services);

        Assert.Throws<InvalidOperationException>(() => MvcRegistration.AddOidcMvc(services));
    }

    [Fact]
    public void TheMinimalApiAdapterAddedAfterTheMvcAdapter_IsRefused()
    {
        var services = new ServiceCollection();
        MvcRegistration.AddOidcMvc(services);

        Assert.Throws<InvalidOperationException>(() => MinimalApiRegistration.AddOidcMinimalApi(services));
    }

    [Fact]
    public void EachAdapterAlone_IsRegistered()
    {
        Assert.Null(Record.Exception(() => MvcRegistration.AddOidcMvc(new ServiceCollection())));
        Assert.Null(Record.Exception(() => MinimalApiRegistration.AddOidcMinimalApi(new ServiceCollection())));
    }
}
