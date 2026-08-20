// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end guard that the MVC adapter applies the CORS policy its controllers reference with
/// <c>[EnableCors]</c>: with no host CORS configuration, a cross-origin GET to the discovery document is
/// answered with an <c>Access-Control-Allow-Origin</c> header. The policy's behaviour (default, host override
/// and the OidcCorsOptions supplement) is unit-tested against AddOidcCors; this only proves the MVC pipeline
/// resolves and applies it.
/// </summary>
public class CorsPolicyTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task Discovery_is_cors_enabled_by_the_adapter_default()
    {
        var client = CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/.well-known/openid-configuration");
        request.Headers.Add("Origin", "https://spa.example.com");
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal("*", response.Headers.GetValues("Access-Control-Allow-Origin").Single());
    }
}
