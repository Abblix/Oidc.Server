// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DeviceAuthorization;

/// <summary>
/// Verifies the startup options validator that guards the device authorization endpoint: an enabled endpoint with no
/// settings is a configuration contradiction that must fail loudly rather than 500 on the first request.
/// </summary>
public class DeviceAuthorizationOptionsValidatorTests
{
    private static readonly DeviceAuthorizationOptionsValidator Validator = new();

    private static DeviceAuthorizationOptions ValidSettings() => new()
    {
        VerificationUri = new Uri("https://auth.example.com/device"),
        CodeLifetime = TimeSpan.FromMinutes(15),
        PollingInterval = TimeSpan.FromSeconds(5),
        DeviceCodeLength = 32,
        UserCodeLength = 8,
    };

    /// <summary>
    /// Settings that leave one of the two brute-force limits unable to fire are refused at startup.
    /// </summary>
    /// <remarks>
    /// Each of these reads as a stricter setting and acts as no setting at all, which is the reason they
    /// cannot be left to a comment. A pause that starts later than the number of attempts the server
    /// records never starts; a per-address cap below one is never reached, where the same number used to
    /// mean "blocked from the first failure"; a window of no length has no attempts in it; and state kept
    /// for less than a window drops attempts while their own window is still running.
    /// </remarks>
    [Theory]
    [InlineData(64, 10, 60, 120)]
    [InlineData(3, 10, 60, 120, 0)]
    [InlineData(3, 10, 60, 120, 64)]
    [InlineData(3, 10, 60, 120, 5, 0)]
    [InlineData(0, 10, 60, 120)]
    [InlineData(3, 0, 60, 120)]
    [InlineData(3, 10, 0, 120)]
    [InlineData(3, 10, 60, 30)]
    public void Fails_when_a_brute_force_limit_cannot_fire(
        int failuresBeforeBackoff, int addressCap, int windowSeconds, int stateSeconds,
        int attemptsPerCode = 5, int serverBudget = 100)
    {
        var settings = ValidSettings();
        settings.MaxUserCodeAttempts = attemptsPerCode;
        settings.MaxFailedAttemptsPerWindow = serverBudget;
        settings.MaxFailuresBeforeBackoff = failuresBeforeBackoff;
        settings.MaxAddressFailuresPerWindow = addressCap;
        settings.RateLimitWindow = TimeSpan.FromSeconds(windowSeconds);
        settings.RateLimitRetention = TimeSpan.FromSeconds(stateSeconds);

        var options = new OidcOptions { EnabledEndpoints = OidcEndpoints.All, DeviceAuthorization = settings };

        Assert.True(Validator.Validate(null, options).Failed);
    }

    /// <summary>
    /// Durations that leave a limit unable to fire, or destroy the records the limits are kept in, are
    /// refused at startup.
    /// </summary>
    /// <remarks>
    /// A code lifetime of no length is not a lax setting, it is an endpoint that cannot work: every code is
    /// expired at the moment it is issued, and that lifetime is also what each attempt record is given, so
    /// no count survives the attempt that made it.
    /// <para>
    /// A backoff ceiling and a polling interval of no length are deliberately NOT refused - those are
    /// choices, and one of them is what a scenario in this repository's own end-to-end suite sets so its
    /// polls need not wait. Measured: refusing them turned that suite red. What the validator must ACCEPT
    /// is pinned by the row below, because a comment saying "deliberately not refused" cannot go red.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(3600, 5, 0)]
    public void Fails_when_a_duration_switches_a_limit_off(
        int backoffCapSeconds, int pollingSeconds, int codeLifetimeMinutes)
    {
        var settings = ValidSettings();
        settings.MaxBackoffDuration = TimeSpan.FromSeconds(backoffCapSeconds);
        settings.PollingInterval = TimeSpan.FromSeconds(pollingSeconds);
        settings.CodeLifetime = TimeSpan.FromMinutes(codeLifetimeMinutes);

        var options = new OidcOptions { EnabledEndpoints = OidcEndpoints.All, DeviceAuthorization = settings };

        Assert.True(Validator.Validate(null, options).Failed);
    }

    /// <summary>
    /// Settings the validator must ACCEPT, including the two it would be easiest to mistake for errors.
    /// </summary>
    /// <remarks>
    /// A startup refusal has two sides and only one of them is a list of wrong values; the other is every
    /// configuration that must keep working, and it is the side with no natural place to be written down.
    /// Both refusals this branch had to withdraw were on this side - a host legitimately polls as fast as
    /// it likes, and a host may lean on the other limits instead of a growing pause. Each was written from
    /// intent, read as obviously safe, and broke a caller in this repository.
    /// <para>
    /// Retention equal to the window belongs here for a different reason: it is the boundary the refusal
    /// stops at. A record claimed at any instant inside a window outlives that window when the retention is
    /// one window long, so nothing is dropped while its own window runs, and refusing equality would refuse
    /// a setting that works.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("polling interval of no length")]
    [InlineData("backoff ceiling of no length")]
    [InlineData("retention equal to the window")]
    public void Succeeds_for_settings_that_only_look_like_mistakes(string setting)
    {
        var settings = ValidSettings();
        switch (setting)
        {
            case "polling interval of no length":
                settings.PollingInterval = TimeSpan.Zero;
                break;
            case "backoff ceiling of no length":
                settings.MaxBackoffDuration = TimeSpan.Zero;
                break;
            case "retention equal to the window":
                settings.RateLimitRetention = settings.RateLimitWindow;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(setting), setting, null);
        }

        var options = new OidcOptions { EnabledEndpoints = OidcEndpoints.All, DeviceAuthorization = settings };

        Assert.True(Validator.Validate(null, options).Succeeded);
    }

    /// <summary>
    /// The cap one address gets is the narrower of the two on the numbers shipped, and a host is free to
    /// set it above the budget the whole server shares.
    /// </summary>
    /// <remarks>
    /// Which of them binds first is what the limiter's own remark tells a reader, and it reads as a
    /// property of the code where it is a property of two defaults nothing relates.
    /// </remarks>
    [Fact]
    public void The_address_cap_is_the_narrower_shipped_number_and_nothing_holds_it_there()
    {
        var settings = ValidSettings();

        Assert.True(settings.MaxAddressFailuresPerWindow < settings.MaxFailedAttemptsPerWindow);

        settings.MaxAddressFailuresPerWindow = settings.MaxFailedAttemptsPerWindow + 1;

        var options = new OidcOptions { EnabledEndpoints = OidcEndpoints.All, DeviceAuthorization = settings };

        Assert.True(Validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void Fails_when_device_endpoint_enabled_but_settings_absent()
    {
        var options = new OidcOptions { EnabledEndpoints = OidcEndpoints.All, DeviceAuthorization = null };

        Assert.True(Validator.Validate(null, options).Failed);
    }

    [Fact]
    public void Succeeds_when_device_endpoint_disabled_even_without_settings()
    {
        var options = new OidcOptions
        {
            EnabledEndpoints = OidcEndpoints.All & ~OidcEndpoints.DeviceAuthorization,
            DeviceAuthorization = null,
        };

        Assert.True(Validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void Succeeds_when_device_endpoint_enabled_and_settings_present()
    {
        var options = new OidcOptions { EnabledEndpoints = OidcEndpoints.All, DeviceAuthorization = ValidSettings() };

        Assert.True(Validator.Validate(null, options).Succeeded);
    }
}
