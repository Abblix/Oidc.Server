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
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A configured client's refresh token reuse policy is checked at startup, rather than when the client is first
/// issued a refresh token.
/// </summary>
public class RefreshTokenReusePolicyValidatorTests
{
    [Fact]
    public void AnUndefinedPolicy_IsRefused()
    {
        var options = new OidcOptions
        {
            Clients =
            [
                new ClientInfo("web"),
                new ClientInfo("mobile") { RefreshToken = new RefreshTokenOptions { ReusePolicy = (RefreshTokenReusePolicy)42 } },
            ],
        };

        Assert.True(new RefreshTokenReusePolicyValidator().Validate(null, options).Failed);
    }

    [Theory]
    [InlineData(RefreshTokenReusePolicy.WhenSenderConstrained)]
    [InlineData(RefreshTokenReusePolicy.Reuse)]
    [InlineData(RefreshTokenReusePolicy.Rotate)]
    public void ADefinedPolicy_PassesTheCheck(RefreshTokenReusePolicy policy)
    {
        var options = new OidcOptions
        {
            Clients = [new ClientInfo("web") { RefreshToken = new RefreshTokenOptions { ReusePolicy = policy } }],
        };

        Assert.True(new RefreshTokenReusePolicyValidator().Validate(null, options).Succeeded);
    }
}
