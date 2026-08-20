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
