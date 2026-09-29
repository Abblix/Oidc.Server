// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Issuer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Issuer;

/// <summary>
/// A server without tenants serves its issuer's settings from its options as they are now.
/// </summary>
public class OptionsIssuerSettingsTests
{
    [Fact]
    public void AReloadedSetting_ReachesTheIssuersSettings()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["LoginUri"] = "https://auth.example.com/login" })
            .Build();
        var services = new ServiceCollection();
        services.Configure<OidcOptions>(configuration);
        services.AddIssuer();
        using var provider = services.BuildServiceProvider();
        var settings = provider.GetRequiredService<IIssuerSettings>();
        Assert.Equal(new Uri("https://auth.example.com/login"), settings.LoginUri);

        configuration["LoginUri"] = "https://auth.example.com/sign-in";
        configuration.Reload();

        Assert.Equal(new Uri("https://auth.example.com/sign-in"), settings.LoginUri);
    }
}
