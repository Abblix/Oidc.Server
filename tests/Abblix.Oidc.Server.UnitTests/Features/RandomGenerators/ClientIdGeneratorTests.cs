// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.RandomGenerators;

/// <summary>
/// A generated client identifier takes the length the settings for new clients name when it is generated, so settings
/// changed after the generator was built, as a configuration reload changes them, decide the next identifier.
/// </summary>
public class ClientIdGeneratorTests
{
    [Fact]
    public void AnIdentifier_TakesTheLengthInForceWhenItIsGenerated()
    {
        var settings = new OidcOptions { NewClientOptions = new NewClientOptions { ClientId = new ClientIdOptions { Length = 16 } } };
        var generator = new ClientIdGenerator(Mock.Of<IOptionsMonitor<OidcOptions>>(monitor => monitor.CurrentValue == settings));
        var first = generator.GenerateClientId();

        settings.NewClientOptions = new NewClientOptions { ClientId = new ClientIdOptions { Length = 32 } };
        var second = generator.GenerateClientId();

        Assert.True(second.Length > first.Length, $"{first.Length} then {second.Length}");
    }
}
