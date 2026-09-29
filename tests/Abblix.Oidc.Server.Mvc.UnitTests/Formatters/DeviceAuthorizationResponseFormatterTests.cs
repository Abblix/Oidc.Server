// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;
using CoreResponse = Abblix.Oidc.Server.Model.DeviceAuthorizationResponse;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Formatters;

/// <summary>
/// Unit tests for <see cref="DeviceAuthorizationResponseFormatter"/>: the RFC 8628 section 3.2 response goes out
/// as the endpoint's processor completed it, the verification pages included.
/// </summary>
public class DeviceAuthorizationResponseFormatterTests
{
    [Fact]
    public async Task FormatResponseAsync_SendsTheResponseAsTheProcessorCompletedIt()
    {
        var completed = new CoreResponse
        {
            DeviceCode = "device-code-1",
            UserCode = "WDJB-MJHT",
            VerificationUri = new Uri("https://auth.example.com/tenants/acme/device"),
            VerificationUriComplete = new Uri("https://auth.example.com/tenants/acme/device?user_code=WDJB-MJHT"),
            ExpiresIn = TimeSpan.FromMinutes(15),
            Interval = TimeSpan.FromSeconds(5),
        };

        var result = await new DeviceAuthorizationResponseFormatter().FormatResponseAsync(
            new DeviceAuthorizationRequest(),
            completed);

        var ok = Assert.IsType<OkObjectResult>(result);
        Assert.Same(completed, ok.Value);
    }
}
