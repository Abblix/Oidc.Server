// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using CoreResponse = Abblix.Oidc.Server.Model.DeviceAuthorizationResponse;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Formatters;

/// <summary>
/// Unit tests for <see cref="DeviceAuthorizationResponseFormatter"/> verifying the RFC 8628 section 3.2
/// response shape, in particular that verification_uri_complete carries the user code so capable
/// devices can render a direct link or QR code.
/// </summary>
public class DeviceAuthorizationResponseFormatterTests
{
    private static DeviceAuthorizationResponseFormatter CreateFormatter(Uri verificationUri)
        => new(Options.Create(new OidcOptions
        {
            DeviceAuthorization = new DeviceAuthorizationOptions
            {
                VerificationUri = verificationUri,
                CodeLifetime = TimeSpan.FromMinutes(15),
                PollingInterval = TimeSpan.FromSeconds(5),
                DeviceCodeLength = 32,
                UserCodeLength = 8,
            },
        }));

    [Fact]
    public async Task FormatResponseAsync_PopulatesVerificationUriComplete()
    {
        var formatter = CreateFormatter(new Uri("https://auth.example.com/device"));
        Result<CoreResponse, OidcError> coreResponse =
            new CoreResponse { DeviceCode = "device-code-1", UserCode = "WDJB-MJHT" };

        var result = await formatter.FormatResponseAsync(new DeviceAuthorizationRequest(), coreResponse);

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<CoreResponse>(ok.Value);
        Assert.Equal(new Uri("https://auth.example.com/device"), response.VerificationUri);
        Assert.Equal(
            new Uri("https://auth.example.com/device?user_code=WDJB-MJHT"),
            response.VerificationUriComplete);
    }
}
