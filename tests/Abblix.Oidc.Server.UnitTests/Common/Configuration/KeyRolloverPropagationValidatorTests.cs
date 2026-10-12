// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A negative propagation window is refused at startup; no window at all is a deployment whose clients do not cache
/// the key set, and is accepted.
/// </summary>
public class KeyRolloverPropagationValidatorTests
{
    [Theory]
    [InlineData(-1, true)]
    [InlineData(0, false)]
    [InlineData(3600, false)]
    public void ANegativeWindow_IsRefused(int seconds, bool refused)
    {
        var result = new KeyRolloverPropagationValidator().Validate(
            null, new OidcOptions { KeyRolloverPropagation = TimeSpan.FromSeconds(seconds) });

        Assert.Equal(refused, result.Failed);
    }

    [Fact]
    public void TheServerRefusesANegativeWindowWhenItsOptionsAreRead()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(TimeProvider.System);
        services.AddOptions<OidcOptions>().Configure(options =>
        {
            options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)];
            options.KeyRolloverPropagation = TimeSpan.FromSeconds(-1);
        });
        services.AddJsonWebTokens();
        services.AddIssuer();
        services.AddAuthServiceJwt();

        using var provider = services.BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
    }
}
