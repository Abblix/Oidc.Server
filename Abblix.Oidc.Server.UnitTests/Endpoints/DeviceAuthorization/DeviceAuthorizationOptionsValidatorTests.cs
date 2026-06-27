// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
