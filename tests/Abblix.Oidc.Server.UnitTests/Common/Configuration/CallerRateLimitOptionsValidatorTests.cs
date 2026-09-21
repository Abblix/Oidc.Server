// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A caller budget that would refuse everybody is refused at startup, in front of whoever wrote the number,
/// rather than at the first request anyone makes.
/// </summary>
public class CallerRateLimitOptionsValidatorTests
{
    private static ValidateOptionsResult Validate(CallerRateLimitOptions rateLimit)
        => new CallerRateLimitOptionsValidator().Validate(null, new OidcOptions { CallerRateLimit = rateLimit });

    [Fact]
    public void The_default_budget_is_accepted()
    {
        Assert.False(Validate(new CallerRateLimitOptions()).Failed);
    }

    /// <summary>
    /// No limit at all is a deliberate choice, not a misconfiguration: it is how a host keeps the behavior of
    /// versions before this setting. The window is then not consulted, so nothing about it can refuse startup.
    /// </summary>
    [Fact]
    public void No_limit_is_accepted_whatever_the_window_says()
    {
        Assert.False(
            Validate(new CallerRateLimitOptions { PermitLimit = null, Window = TimeSpan.Zero }).Failed);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void A_limit_that_permits_nothing_is_refused(int permitLimit)
    {
        var refused = Validate(new CallerRateLimitOptions { PermitLimit = permitLimit });

        Assert.True(refused.Failed);
        Assert.Contains(nameof(CallerRateLimitOptions.PermitLimit), refused.FailureMessage);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void A_window_of_no_length_is_refused(int seconds)
    {
        var refused = Validate(new CallerRateLimitOptions { Window = TimeSpan.FromSeconds(seconds) });

        Assert.True(refused.Failed);
        Assert.Contains(nameof(CallerRateLimitOptions.Window), refused.FailureMessage);
    }

    /// <summary>
    /// The shipped composition refuses the value too, which a validator nobody registers would not. Both
    /// endpoints register it, so the check is asked for through each of them.
    /// </summary>
    [Fact]
    public void The_composition_refuses_a_limit_that_permits_nothing()
    {
        var services = new ServiceCollection();
        services.AddIntrospection();
        services.AddRevocation();
        services.AddOidcCore(options => options.CallerRateLimit.PermitLimit = 0);
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);

        Assert.Contains(refusal.Failures, failure => failure.Contains(nameof(CallerRateLimitOptions.PermitLimit)));
    }
}
