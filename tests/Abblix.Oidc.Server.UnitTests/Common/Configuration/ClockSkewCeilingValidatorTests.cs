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
/// The validator holds the sixty-second bound whatever a caller asks for, so this guard is not what
/// makes the requirement true. It is what keeps a deployment from reading a setting back and
/// believing a number the validator will not honour.
/// </summary>
public class ClockSkewCeilingValidatorTests
{
    private static ValidateOptionsResult Validate(TimeSpan skew)
        => new ClockSkewCeilingValidator().Validate(
            null,
            new OidcOptions { JwtBearer = new JwtBearerOptions { ClockSkew = skew } });

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
    /// A negative window refuses an assertion valid at the instant its request arrives, which reads
    /// as an intermittent fault rather than as a setting.
    /// </summary>
    [Fact]
    public void Negative_Fails()
    {
        Assert.True(Validate(TimeSpan.FromSeconds(-1)).Failed);
    }

    /// <summary>
    /// The default a host gets without doing anything passes its own guard. One that failed startup
    /// would be a defect nobody meets until they read the options object.
    /// </summary>
    [Fact]
    public void TheDefault_IsSixtySecondsAndPasses()
    {
        var options = new OidcOptions();

        Assert.Equal(TimeSpan.FromSeconds(60), options.JwtBearer.ClockSkew);
        Assert.False(new ClockSkewCeilingValidator().Validate(null, options).Failed);
    }
}
