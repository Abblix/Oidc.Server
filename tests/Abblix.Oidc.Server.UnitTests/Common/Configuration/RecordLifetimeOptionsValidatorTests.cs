// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A retention at which the record of a session's clients would expire as it is written is refused at startup.
/// </summary>
public class RecordLifetimeOptionsValidatorTests
{
    private static bool Fails(TimeSpan retention)
        => new RecordLifetimeOptionsValidator()
            .Validate(null, new OidcOptions { SessionClientsRetention = retention })
            .Failed;

    [Fact]
    public void The_default_retention_is_accepted()
    {
        Assert.False(new RecordLifetimeOptionsValidator().Validate(null, new OidcOptions()).Failed);
    }

    [Fact]
    public void The_shortest_positive_retention_is_accepted()
    {
        Assert.False(Fails(TimeSpan.FromTicks(1)));
    }

    [Fact]
    public void A_retention_of_zero_is_refused()
    {
        Assert.True(Fails(TimeSpan.Zero));
    }

    [Fact]
    public void A_negative_retention_is_refused()
    {
        Assert.True(Fails(TimeSpan.FromDays(-1)));
    }

    /// <summary>
    /// The shipped composition refuses the value too, which a validator nobody registers would not.
    /// </summary>
    [Fact]
    public void The_composition_refuses_a_retention_of_zero()
    {
        var services = new ServiceCollection();
        services.AddOidcCore(options => options.SessionClientsRetention = TimeSpan.Zero);
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);

        Assert.Contains(refusal.Failures, failure => failure.Contains(nameof(OidcOptions.SessionClientsRetention)));
    }

    /// <summary>
    /// The same refusal covers the logout confirmation's lifetime, whose record the storage would decline to write
    /// at all: without this, a deployment boots and every logout question faults instead.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void A_logout_confirmation_lifetime_that_keeps_nothing_is_refused(int minutes)
    {
        var refused = new RecordLifetimeOptionsValidator().Validate(
            null,
            new OidcOptions { LogoutConfirmationLifetime = TimeSpan.FromMinutes(minutes) });

        Assert.True(refused.Failed);
        Assert.Contains(nameof(OidcOptions.LogoutConfirmationLifetime), refused.FailureMessage);
    }

    /// <summary>
    /// The shipped composition refuses it too, which a check nobody registers would not.
    /// </summary>
    [Fact]
    public void The_composition_refuses_a_logout_confirmation_lifetime_of_zero()
    {
        var services = new ServiceCollection();
        services.AddOidcCore(options => options.LogoutConfirmationLifetime = TimeSpan.Zero);
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);

        Assert.Contains(
            refusal.Failures,
            failure => failure.Contains(nameof(OidcOptions.LogoutConfirmationLifetime)));
    }
}
