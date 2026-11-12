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

    private static ValidateOptionsResult ValidateIssued(TimeSpan skew)
        => new ClockSkewValidator().Validate(null, new OidcOptions { IssuedTokenClockSkew = skew });

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

    /// <summary>
    /// A negative tolerance for the server's own tokens refuses one even on the node that issued it, so it is refused
    /// at startup, naming the setting.
    /// </summary>
    [Fact]
    public void ANegativeToleranceForIssuedTokens_Fails_NamingTheSetting()
    {
        var result = ValidateIssued(TimeSpan.FromSeconds(-1));

        Assert.True(result.Failed);
        Assert.Contains(nameof(OidcOptions.IssuedTokenClockSkew), result.FailureMessage);
    }

    /// <summary>
    /// Zero and positive tolerances for the server's own tokens pass, so the refusal above cannot be satisfied by a
    /// guard that refuses everything.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(60)]
    public void AToleranceForIssuedTokensOfZeroOrMore_Succeeds(int seconds)
    {
        Assert.False(ValidateIssued(TimeSpan.FromSeconds(seconds)).Failed);
    }
}
