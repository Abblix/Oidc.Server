// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A negative clock skew is refused whatever any tenant's profile says: it is not a loosening somebody may want but
/// a window that refuses an assertion valid at the instant its request arrives, which reads as an intermittent fault
/// rather than as a setting.
/// </summary>
public class ClockSkewValidatorTests
{
    private static ValidateOptionsResult Validate(TimeSpan? skew)
        => new ClockSkewValidator().Validate(
            null,
            new OidcOptions { JwtBearer = new JwtBearerOptions { ClockSkew = skew } });

    [Fact]
    public void Negative_Fails()
    {
        Assert.True(Validate(TimeSpan.FromSeconds(-1)).Failed);
    }

    /// <summary>
    /// Zero, any positive value and nothing set pass, so <see cref="Negative_Fails"/> cannot be satisfied by a guard
    /// that refuses everything. What a positive value may be under a bounding profile is the business of
    /// <see cref="ClockSkewCeilingCheck"/>, judged per tenant.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(60)]
    [InlineData(3600)]
    public void ZeroOrMore_Succeeds(int seconds)
    {
        Assert.False(Validate(TimeSpan.FromSeconds(seconds)).Failed);
    }

    [Fact]
    public void NothingSet_Succeeds()
    {
        Assert.False(Validate(null).Failed);
    }
}
