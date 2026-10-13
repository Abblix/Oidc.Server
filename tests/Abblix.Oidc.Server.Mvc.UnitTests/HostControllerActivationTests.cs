// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

/// <summary>
/// The package does not change how the host's own controllers are created: a controller the host brings in after
/// registering the package, which no service registration names, is created as plain MVC creates it.
/// </summary>
public class HostControllerActivationTests
{
    [Fact]
    public void AHostControllerNoServiceNamesIsCreated()
    {
        var services = new ServiceCollection().AddLogging().AddOidcMvc().BuildServiceProvider();

        var controller = services.GetRequiredService<IControllerActivator>().Create(new ControllerContext(
            new ActionContext(
                new DefaultHttpContext { RequestServices = services },
                new RouteData(),
                new ControllerActionDescriptor { ControllerTypeInfo = typeof(HostController).GetTypeInfo() })));

        Assert.IsType<HostController>(controller);
    }

    /// <summary>A controller a host declares itself.</summary>
    public sealed class HostController : ControllerBase;
}
