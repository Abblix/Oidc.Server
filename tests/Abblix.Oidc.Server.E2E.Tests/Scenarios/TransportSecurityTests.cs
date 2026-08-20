// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Diagnostics.CodeAnalysis;
using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end guard that the MVC adapter gates its public metadata endpoints on HTTPS. DiscoveryController
/// (serving discovery and JWKS) carries <c>[RequireHttps]</c> like the credential-bearing controllers, so a
/// cleartext GET is redirected to the https URL rather than served: over plain HTTP a man-in-the-middle could
/// rewrite the advertised endpoints or signing keys and steer clients onto attacker infrastructure. This pins the
/// MVC adapter to the same all-endpoints transport policy as the Minimal API adapter.
/// </summary>
public class TransportSecurityTests(TestFactory factory) : TestBase(factory)
{
    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-authorization-server")]
    [InlineData("/.well-known/jwks")]
    [SuppressMessage("Minor Code Smell", "S1075", Justification = "In-memory TestServer http base address; not a deployment URL.")]
    public async Task Non_https_metadata_get_is_redirected_to_https(string path)
    {
        var httpClient = Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("http://localhost"),
        });

        // TestServer honours the request scheme, so Request.IsHttps is false here and [RequireHttps] redirects.
        var response = await httpClient.GetAsync(path, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal(Uri.UriSchemeHttps, response.Headers.Location!.Scheme);
    }
}
