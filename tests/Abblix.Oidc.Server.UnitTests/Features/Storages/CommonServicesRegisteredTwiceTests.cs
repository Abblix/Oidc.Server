// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Storages;

/// <summary>
/// The services every feature relies on, registered a second time, as a host calling the registration before the
/// server's own call does.
/// </summary>
public class CommonServicesRegisteredTwiceTests
{
    /// <summary>
    /// An entity a tenant keeps is stored under the tenant's key once: a second registration does not wrap the storage
    /// in the tenant's form again.
    /// </summary>
    [Fact]
    public async Task AnEntity_IsKeptUnderTheTenantsKeyOnce()
    {
        var keys = new List<string>();
        var shared = new Mock<IEntityStorage>();
        shared
            .Setup(storage => storage.SetAsync(
                Capture.In(keys), It.IsAny<string>(), It.IsAny<StorageOptions>(), It.IsAny<CancellationToken?>()))
            .Returns(Task.CompletedTask);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddKeyedSingleton(TenantServiceKeys.Shared, shared.Object);
        services.AddCommonServices();
        services.AddCommonServices();
        await using var provider = services.BuildServiceProvider();

        using (TenantScope.Enter(new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com") }))
        {
            await provider.GetRequiredService<IEntityStorage>().SetAsync(
                "entity", "value", new StorageOptions(), TestContext.Current.CancellationToken);
        }

        Assert.Equal("tenant:acme:entity", Assert.Single(keys));
    }
}
