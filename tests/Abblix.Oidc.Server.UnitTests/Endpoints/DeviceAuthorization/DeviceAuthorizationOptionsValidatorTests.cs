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
        settings.MaxIpFailuresPerMinute = addressCap;
        settings.RateLimitWindow = TimeSpan.FromSeconds(windowSeconds);
        settings.IpRateLimitStateExpiration = TimeSpan.FromSeconds(stateSeconds);

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
    /// choices, and one of them is what this repository's own end-to-end host uses so it need not wait
    /// between polls. Measured: refusing them turned that suite red.
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
