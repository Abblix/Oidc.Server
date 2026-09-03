// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// The ceiling exists so the freshness check cannot be turned off by configuration, which is why it
/// is refused at startup rather than at the first request.
/// </summary>
public class ClockOffsetToleranceValidatorTests
{
    private static ValidateOptionsResultShape Validate(TimeSpan tolerance)
    {
        var result = new ClockOffsetToleranceValidator()
            .Validate(null, new OidcOptions { ClockOffsetTolerance = tolerance });

        return new ValidateOptionsResultShape(result.Failed, result.FailureMessage);
    }

    private sealed record ValidateOptionsResultShape(bool Failed, string? Message);

    /// <summary>
    /// The value FAPI 2.0 section 5.3.2.1 names, the ceiling it names, and the ends of the range
    /// between them all pass. Without these the refusals below would be satisfied by a validator
    /// that refuses everything.
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
    /// A second past the ceiling is refused, and the refusal names the property so the operator
    /// knows what to edit rather than which line threw.
    /// </summary>
    [Theory]
    [InlineData(61)]
    [InlineData(3600)]
    public void AboveTheCeiling_Fails(int seconds)
    {
        var result = Validate(TimeSpan.FromSeconds(seconds));

        Assert.True(result.Failed);
        Assert.Contains(nameof(OidcOptions.ClockOffsetTolerance), result.Message!);
    }

    /// <summary>
    /// The other end is refused for the opposite reason: a negative window narrows the check past
    /// exactness and refuses a token issued at the instant its request arrives, which reads as an
    /// intermittent fault rather than as a setting.
    /// </summary>
    [Fact]
    public void Negative_Fails()
    {
        var result = Validate(TimeSpan.FromSeconds(-1));

        Assert.True(result.Failed);
        Assert.Contains(nameof(OidcOptions.ClockOffsetTolerance), result.Message!);
    }

    /// <summary>
    /// The default a host gets without doing anything is the interoperable value the specification
    /// names, and it passes its own validator. A default that failed startup would be a defect
    /// nobody meets until they read the options object.
    /// </summary>
    [Fact]
    public void TheDefault_IsTenSecondsAndPasses()
    {
        var options = new OidcOptions();

        Assert.Equal(TimeSpan.FromSeconds(10), options.ClockOffsetTolerance);
        Assert.False(new ClockOffsetToleranceValidator().Validate(null, options).Failed);
    }
}
