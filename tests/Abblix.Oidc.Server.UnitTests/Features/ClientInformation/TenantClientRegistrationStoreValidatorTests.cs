// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// A store of registrations for the tenants is served only under multi-tenancy, and refused at startup elsewhere
/// rather than never asked.
/// </summary>
public class TenantClientRegistrationStoreValidatorTests
{
    private static ValidateOptionsResult Validate(bool store, bool multiTenancy)
    {
        var services = new ServiceCollection();
        if (store)
            services.AddSingleton(Mock.Of<ITenantClientRegistrationStore>());
        if (multiTenancy)
            services.AddSingleton(Mock.Of<IValidateOptions<MultiTenancyOptions>>());

        using var provider = services.BuildServiceProvider();
        return new TenantClientRegistrationStoreValidator(provider).Validate(null, new OidcOptions());
    }

    [Fact]
    public void AStoreOnAServerWithoutTenants_IsRefused_NamingIt()
    {
        var result = Validate(store: true, multiTenancy: false);

        Assert.True(result.Failed);
        Assert.Contains(nameof(ITenantClientRegistrationStore), result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [InlineData(false, true)]
    public void AStoreUnderMultiTenancy_OrNoStore_Passes(bool store, bool multiTenancy)
        => Assert.True(Validate(store, multiTenancy).Succeeded);
}
