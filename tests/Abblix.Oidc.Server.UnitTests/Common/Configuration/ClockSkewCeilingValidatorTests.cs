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
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// The validator holds the sixty-second bound whatever a caller asks for, so this guard is not what
/// makes the requirement true. It is what keeps a deployment from reading a setting back and
/// believing a number the validator will not honour.
/// </summary>
public class ClockSkewCeilingValidatorTests
{
    private static ValidateOptionsResult Validate(
        TimeSpan? skew,
        ClientSecurityProfile profile = ClientSecurityProfile.Fapi2)
        => new ClockSkewCeilingValidator().Validate(
            null,
            new OidcOptions
            {
                DefaultSecurityProfile = profile,
                JwtBearer = new JwtBearerOptions { ClockSkew = skew },
            });

    /// <summary>
    /// Both ends of the permitted range and the default pass, so the refusals below cannot be
    /// satisfied by a guard that refuses everything.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(10)]
    [InlineData(59)]
    [InlineData(60)]
    public void WithinTheRange_Succeeds(int seconds)
    {
        Assert.False(Validate(TimeSpan.FromSeconds(seconds)).Failed);
    }

    /// <summary>
    /// A second past the bound is refused, and the message names the setting so the operator edits a
    /// number rather than reads the validator.
    /// </summary>
    [Theory]
    [InlineData(61)]
    [InlineData(300)]
    public void AboveTheCeiling_Fails(int seconds)
    {
        var result = Validate(TimeSpan.FromSeconds(seconds));

        Assert.True(result.Failed);
        Assert.Contains(nameof(JwtBearerOptions.ClockSkew), result.FailureMessage!);
    }

    /// <summary>
    /// Five minutes was the default this change replaced, so it is the value a deployment carrying
    /// the old configuration forward will still be holding.
    /// </summary>
    [Fact]
    public void TheFormerDefault_Fails()
    {
        Assert.True(Validate(TimeSpan.FromMinutes(5)).Failed);
    }

    /// <summary>
    /// And outside a profile that bounds this, the same five minutes pass. RFC 7523 Section 3 allows
    /// for clock skew and names no bound, so a deployment held to no profile is entitled to them -
    /// without this case the guard would be refusing on its own authority rather than the profile's.
    /// </summary>
    [Theory]
    [InlineData(300)]
    [InlineData(3600)]
    public void WithNoProfile_AnythingPasses(int seconds)
    {
        Assert.False(
            Validate(TimeSpan.FromSeconds(seconds), ClientSecurityProfile.None).Failed);
    }

    /// <summary>
    /// A negative value is refused whatever the profile: it is not a loosening somebody may want but
    /// a window that refuses an assertion valid at the instant its request arrives.
    /// </summary>
    [Fact]
    public void WithNoProfile_NegativeStillFails()
    {
        Assert.True(Validate(TimeSpan.FromSeconds(-1), ClientSecurityProfile.None).Failed);
    }

    /// <summary>
    /// A negative window refuses an assertion valid at the instant its request arrives, which reads
    /// as an intermittent fault rather than as a setting.
    /// </summary>
    [Fact]
    public void Negative_Fails()
    {
        Assert.True(Validate(TimeSpan.FromSeconds(-1)).Failed);
    }

    /// <summary>
    /// Nothing set is not a value to refuse: it asks the profile to decide, and what the profile
    /// decides is by construction what the profile allows. Refusing it would fail every deployment
    /// held to a bounding profile over a number nobody chose - which is what a default written into
    /// the options object would have been.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None)]
    [InlineData(ClientSecurityProfile.Fapi2)]
    public void NothingSet_Passes(ClientSecurityProfile profile)
    {
        Assert.False(Validate(null, profile).Failed);
    }

    /// <summary>
    /// And what nothing-set resolves to: this server's own five minutes where no profile bounds it,
    /// and the profile's bound where one does. Without this the guard above would be silent about a
    /// resolution that could be anything.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None, 300)]
    [InlineData(ClientSecurityProfile.Fapi2, 60)]
    public void NothingSet_ResolvesToTheProfilesAnswer(ClientSecurityProfile profile, int seconds)
    {
        var options = new JwtBearerOptions();

        Assert.Equal(TimeSpan.FromSeconds(seconds), options.ResolveClockSkew(profile));
    }

    /// <summary>
    /// A value this deployment set wins over both, which is the point of being able to set one.
    /// </summary>
    [Fact]
    public void AValueSet_WinsOverTheProfile()
    {
        var options = new JwtBearerOptions { ClockSkew = TimeSpan.FromSeconds(30) };

        Assert.Equal(TimeSpan.FromSeconds(30), options.ResolveClockSkew(ClientSecurityProfile.Fapi2));
    }
}
