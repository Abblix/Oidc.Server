// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc;
using Microsoft.AspNetCore.Http;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// Kestrel passes on a request with no host, which HTTP/1.0 allows, and one whose Host header no URI can carry. No
/// address of this server can be built for either, so each transport refuses it as an invalid request before an
/// endpoint, or the HTTPS redirect of a cleartext request, builds one. Compiled into both E2E suites, so it drives
/// the MVC host and the Minimal API host alike.
/// </summary>
public class HostlessRequestTests(TestFactory factory) : TestBase(factory)
{
    [Theory]
    [InlineData("https", "")]
    [InlineData("http", "")]
    [InlineData("https", "auth..example.com")]
    [InlineData("https", "auth.example.com:99999")]
    public async Task ARequestWithNoUsableHost_IsRefusedAsInvalidRequest(string scheme, string host)
    {
        var context = await Factory.Server.SendAsync(
            http =>
            {
                http.Request.Method = HttpMethods.Get;
                http.Request.Scheme = scheme;
                http.Request.Host = new HostString(host);
                http.Request.Path = "/.well-known/openid-configuration";
            },
            TestContext.Current.CancellationToken);

        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
        var body = await JsonNode.ParseAsync(context.Response.Body, cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(ErrorCodes.InvalidRequest, body?[ResponseParameters.Error]?.GetValue<string>());
    }
}
