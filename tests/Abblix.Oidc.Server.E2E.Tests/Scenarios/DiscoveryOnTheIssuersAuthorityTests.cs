// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Json;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A tenant is found by its host alone, so a discovery request naming the issuer's host with another port or in
/// another case reaches it. Every endpoint the document lists is still published on the issuer's scheme, host and
/// port, the spelling the JWT bearer grant and client authentication accept, so a client following the document is
/// never sent to an address those checks refuse. Compiled into both E2E suites, so both adapters answer it.
/// </summary>
public class DiscoveryOnTheIssuersAuthorityTests(TestFactory factory) : TestBase(factory)
{
    [Theory]
    [InlineData("auth.example.com:8443")]
    [InlineData("AUTH.example.com")]
    public async Task EveryEndpoint_IsPublishedOnTheIssuersAuthority_WhateverHostTheRequestNames(string requestHost)
    {
        using var http = CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/.well-known/openid-configuration");
        request.Headers.Host = requestHost;

        using var response = await http.SendAsync(request, TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();
        var document = await response.Content.ReadFromJsonAsync<DiscoveryDocument>(TestContext.Current.CancellationToken);

        Assert.NotNull(document);
        var issuerAuthority = document.Issuer.GetLeftPart(UriPartial.Authority);
        Uri?[] endpoints =
        [
            document.AuthorizationEndpoint,
            document.TokenEndpoint,
            document.RegistrationEndpoint,
            document.PushedAuthorizationRequestEndpoint,
            document.IntrospectionEndpoint,
            document.RevocationEndpoint,
            document.DeviceAuthorizationEndpoint,
            document.BackChannelAuthenticationEndpoint,
            document.EndSessionEndpoint,
            document.CheckSessionIframe,
            document.UserInfoEndpoint,
            document.JwksUri,
        ];
        Assert.All(endpoints, endpoint =>
        {
            Assert.NotNull(endpoint);
            Assert.Equal(issuerAuthority, endpoint.GetLeftPart(UriPartial.Authority));
            Assert.Equal(issuerAuthority + endpoint.AbsolutePath, endpoint.OriginalString);
        });
    }
}
