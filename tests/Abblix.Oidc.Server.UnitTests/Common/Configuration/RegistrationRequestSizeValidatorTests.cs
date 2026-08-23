// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// The startup refusal of a registration body limit no request could satisfy.
/// </summary>
/// <remarks>
/// The value is worth refusing here because neither host reports it as a configuration fault: an MVC host
/// answers 413 to every registration and a minimal API host answers 500, and both read to an operator as the
/// endpoint being broken rather than as a number somebody set wrong.
/// </remarks>
public class RegistrationRequestSizeValidatorTests
{
    private static readonly RegistrationRequestSizeValidator Validator = new();

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(long.MinValue)]
    public void A_non_positive_limit_is_refused(long limit)
    {
        var result = Validator.Validate(null, new OidcOptions { MaxRegistrationRequestSize = limit });

        Assert.True(result.Failed);
        Assert.Contains(nameof(OidcOptions.MaxRegistrationRequestSize), result.FailureMessage);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(128 * 1024)]
    [InlineData(long.MaxValue)]
    public void A_positive_limit_is_accepted(long limit)
    {
        var result = Validator.Validate(null, new OidcOptions { MaxRegistrationRequestSize = limit });

        Assert.True(result.Succeeded);
    }

    /// <summary>
    /// A cleared limit is the one way to say the deployment bounds the body elsewhere, so it must pass -
    /// otherwise the only escape from our bound would be a number, and every number is a bound.
    /// </summary>
    [Fact]
    public void A_cleared_limit_is_accepted()
    {
        var result = Validator.Validate(null, new OidcOptions { MaxRegistrationRequestSize = null });

        Assert.True(result.Succeeded);
    }

    /// <summary>
    /// The default this server ships with survives its own validator. Stated because the two are written in
    /// different files and nothing else makes them agree.
    /// </summary>
    [Fact]
    public void The_shipped_default_is_accepted()
    {
        var result = Validator.Validate(null, new OidcOptions());

        Assert.True(result.Succeeded);
    }
}
