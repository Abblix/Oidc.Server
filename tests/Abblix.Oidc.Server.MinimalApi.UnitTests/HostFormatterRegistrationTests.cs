// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Oidc.Server.AspNetCore.Formatters;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// A host that registers its own response formatter under the shared generic contract before adding the Minimal API
/// adapter keeps it: the adapter adds its default only where no formatter is registered yet.
/// </summary>
public class HostFormatterRegistrationTests
{
    /// <summary>
    /// Every shared formatter contract closed over the Minimal API result type, except the two the adapter
    /// decorates, whose resolved instance is the adapter's decorator around whichever formatter is registered.
    /// </summary>
    public static TheoryData<Type> UndecoratedContracts()
    {
        var anchor = typeof(ITokenResponseFormatter<>);
        Type[] decorated = [typeof(IEndSessionResponseFormatter<>), typeof(ICheckSessionResponseFormatter<>)];
        return new TheoryData<Type>(anchor.Assembly.GetExportedTypes()
            .Where(type => type is { IsInterface: true, IsGenericTypeDefinition: true } &&
                           type.Namespace == anchor.Namespace &&
                           !decorated.Contains(type))
            .Select(type => type.MakeGenericType(typeof(IResult))));
    }

    [Theory]
    [MemberData(nameof(UndecoratedContracts))]
    public void AFormatterTheHostRegisteredFirst_IsTheOneResolved(Type contract)
    {
        var hostFormatter = ((Mock)Activator.CreateInstance(typeof(Mock<>).MakeGenericType(contract))!).Object;

        var services = new ServiceCollection();
        services.AddSingleton(contract, hostFormatter);
        services.AddOidcMinimalApi();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        Assert.Same(hostFormatter, scope.ServiceProvider.GetRequiredService(contract));
    }
}
