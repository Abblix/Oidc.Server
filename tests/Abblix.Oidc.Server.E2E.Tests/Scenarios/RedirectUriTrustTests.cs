// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 9700 section 4.11.2 end to end: anybody may register a client while registration needs no initial access token,
/// so under the server's own policy an erroneous request of such a client is answered by the server,
/// with status 400 and the error in the body, rather than at the redirect URI its registrant chose. A client the host
/// trusts is redirected to as before.
/// </summary>
public class RedirectUriTrustTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// Two erroneous requests of a client registered openly: a response type it may not use, and a code challenge
    /// method the server does not support.
    /// </summary>
    [Theory]
    [InlineData(ResponseTypes.Token, CodeChallengeMethods.S256)]
    [InlineData(ResponseTypes.Code, "S384")]
    public async Task AnErrorForAnOpenlyRegisteredClient_IsAnsweredByTheServer(string responseType, string method)
    {
        await using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.Replace(ServiceDescriptor.Singleton<IRedirectUriTrustPolicy, RedirectUriTrustPolicy>())));
        using var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

        using var response = await AuthorizeAsync(client, responseType, method);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{(int)response.StatusCode}: {body}");
        Assert.Null(response.Headers.Location);
        Assert.NotNull(JsonNode.Parse(body)![ErrorResponse.Parameters.Error]);
    }

    /// <summary>
    /// The same requests of a client the host trusts reach the client's redirect URI, the error in its parameters.
    /// </summary>
    [Theory]
    [InlineData(ResponseTypes.Token, CodeChallengeMethods.S256)]
    [InlineData(ResponseTypes.Code, "S384")]
    public async Task AnErrorForATrustedClient_IsRedirectedToIt(string responseType, string method)
    {
        using var client = CreateClient();

        using var response = await AuthorizeAsync(client, responseType, method);

        var location = response.Headers.Location;
        Assert.NotNull(location);
        Assert.StartsWith(TestConstants.RedirectUri, location.OriginalString);
        Assert.Contains(ResponseParameters.Error + "=", location.OriginalString);
    }

    private static async Task<HttpResponseMessage> AuthorizeAsync(HttpClient client, string responseType, string method)
    {
        var discovery = await FetchDiscoveryAsync(client);
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RequestMembers.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
            [RequestMembers.GrantTypes] = new JsonArray(GrantTypes.AuthorizationCode),
            [RequestMembers.ResponseTypes] = new JsonArray(ResponseTypes.Code),
        });

        var parameters = new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = registered[ResponseMembers.ClientId]!.GetValue<string>(),
            [AuthorizationRequest.Parameters.ResponseType] = responseType,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = method,
        };
        return await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters), TestContext.Current.CancellationToken);
    }
}
