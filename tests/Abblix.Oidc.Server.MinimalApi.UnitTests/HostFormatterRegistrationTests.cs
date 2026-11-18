// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.AspNetCore.Formatters;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// A host that registers its own response formatter under the shared generic contract before adding the Minimal API
/// adapter keeps it: the adapter adds its default only where no formatter is registered yet. A formatter closed
/// over a result type Minimal API never resolves is refused rather than left unused.
/// </summary>
public class HostFormatterRegistrationTests
{
    /// <summary>
    /// Every shared formatter contract closed over the Minimal API result type, except the two the adapter decorates,
    /// whose resolved instance is the adapter's decorator around whichever formatter is registered.
    /// </summary>
    public static TheoryData<Type> UndecoratedContracts()
    {
        Type[] decorated = [typeof(IEndSessionResponseFormatter<>), typeof(ICheckSessionResponseFormatter<>)];
        return new TheoryData<Type>(SharedContracts()
            .Where(contract => !decorated.Contains(contract))
            .Select(contract => contract.MakeGenericType(typeof(IResult))));
    }

    /// <summary>Every shared formatter contract closed over a result type Minimal API endpoints never return.</summary>
    public static TheoryData<Type> ContractsClosedOverAnotherResult()
        => new(SharedContracts().Select(contract => contract.MakeGenericType(typeof(ActionResult))));

    [Theory]
    [MemberData(nameof(UndecoratedContracts))]
    public void AFormatterTheHostRegisteredFirst_IsTheOneResolved(Type contract)
    {
        var hostFormatter = MockOf(contract);

        var services = new ServiceCollection();
        services.AddSingleton(contract, hostFormatter);
        services.AddOidcMinimalApi();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        Assert.Same(hostFormatter, scope.ServiceProvider.GetRequiredService(contract));
    }

    [Fact]
    public async Task AnEndSessionFormatterTheHostRegisteredFirst_IsTheOneTheAdapterDecorates()
    {
        var hosted = Results.Ok();
        var hostFormatter = new Mock<IEndSessionResponseFormatter<IResult>>();
        hostFormatter
            .Setup(formatter => formatter.FormatResponseAsync(
                It.IsAny<EndSessionRequest>(), It.IsAny<Result<IEndSessionResponse, OidcError>>()))
            .ReturnsAsync(hosted);

        var services = new ServiceCollection();
        services.AddSingleton(hostFormatter.Object);
        services.AddOidcMinimalApi();
        services.AddSingleton(Mock.Of<ISessionManagementService>());
        services.AddSingleton(Mock.Of<ITenantAccessor>());

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var formatter = scope.ServiceProvider.GetRequiredService<IEndSessionResponseFormatter<IResult>>();
        var result = await formatter.FormatResponseAsync(
            new EndSessionRequest(), new OidcError(Abblix.Oidc.ErrorCodes.InvalidRequest, "refused"));

        Assert.Same(hosted, result);
    }

    [Fact]
    public async Task ACheckSessionFormatterTheHostRegisteredFirst_IsTheOneTheAdapterDecorates()
    {
        var hosted = Results.Ok();
        var hostFormatter = new Mock<ICheckSessionResponseFormatter<IResult>>();
        hostFormatter
            .Setup(formatter => formatter.FormatResponseAsync(It.IsAny<CheckSessionResponse>()))
            .ReturnsAsync(hosted);

        var services = new ServiceCollection();
        services.AddSingleton(hostFormatter.Object);
        services.AddOidcMinimalApi();
        services.AddSingleton(Mock.Of<ITenantCatalog>());
        services.AddSingleton(Mock.Of<ITenantAccessor>(accessor => accessor.Current == new TenantContext
        {
            Tenant = new TenantDefinition { Id = "acme", Issuer = new Uri("https://auth.example.com") },
        }));

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var formatter = scope.ServiceProvider.GetRequiredService<ICheckSessionResponseFormatter<IResult>>();
        var result = await formatter.FormatResponseAsync(new CheckSessionResponse("<html/>", "check-session"));

        Assert.Same(hosted, result);
    }

    [Theory]
    [MemberData(nameof(ContractsClosedOverAnotherResult))]
    public void AFormatterClosedOverAnotherResultType_IsRefused(Type contract)
    {
        var services = new ServiceCollection();
        services.AddSingleton(contract, MockOf(contract));

        Assert.Throws<InvalidOperationException>(() => services.AddOidcMinimalApi());
    }

    [Fact]
    public void ATokenFormatterClosedOverTheTypedMvcResult_IsRefused()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<ITokenResponseFormatter<ActionResult<TokenResponse>>>());

        Assert.Throws<InvalidOperationException>(() => services.AddOidcMinimalApi());
    }

    private static Type[] SharedContracts()
    {
        var anchor = typeof(ITokenResponseFormatter<>);
        return anchor.Assembly.GetExportedTypes()
            .Where(type => type is { IsInterface: true, IsGenericTypeDefinition: true } &&
                           type.Namespace == anchor.Namespace)
            .ToArray();
    }

    private static object MockOf(Type contract)
        => ((Mock)Activator.CreateInstance(typeof(Mock<>).MakeGenericType(contract))!).Object;
}
