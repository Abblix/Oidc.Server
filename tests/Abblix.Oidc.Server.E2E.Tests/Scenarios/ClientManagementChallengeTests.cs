// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.MinimalApi.UnitTests;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// The challenge the client configuration endpoint (RFC 7592 sections 2.1 to 2.3) and the registration endpoint that
/// requires an initial access token (RFC 7591 section 3) answer a request without a usable token with: both send a
/// token error "as described in" RFC 6750.
/// </summary>
public class ClientManagementChallengeTests(TestFactory factory) : TestBase(factory)
{
    private const string RealmAttribute = "realm";

    private const string AccessTokenParameter = "access_token";

    public static TheoryData<string, string> RequestsLackingAuthentication()
    {
        var data = new TheoryData<string, string>();
        foreach (var method in new[] { "GET", "PUT", "DELETE", "POST" })
        {
            foreach (var credentials in new[] { NoAuthorization, BasicCredentials, BasicSchemeAlone, TokenInTheQuery })
                data.Add(method, credentials);
        }

        return data;
    }

    private const string NoAuthorization = nameof(NoAuthorization);
    private const string BasicCredentials = nameof(BasicCredentials);
    private const string BasicSchemeAlone = nameof(BasicSchemeAlone);
    private const string TokenInTheQuery = nameof(TokenInTheQuery);
    private const string BearerSchemeAlone = nameof(BearerSchemeAlone);

    /// <summary>
    /// RFC 6750 section 3.1: "If the request lacks any authentication information (e.g., the client was unaware that
    /// authentication is necessary or attempted using an unsupported authentication method), the resource server SHOULD
    /// NOT include an error code or other error information." Section 3: the scheme "MUST be followed by one or more
    /// auth-param values", so the bare challenge carries the realm. A token in the query is not read here at all, so the
    /// request carrying one lacks authentication information as one carrying nothing does.
    /// </summary>
    [Theory]
    [MemberData(nameof(RequestsLackingAuthentication))]
    public async Task A_request_lacking_authentication_gets_a_bare_bearer_challenge(string method, string credentials)
    {
        var registration = method == HttpMethod.Post.Method;
        await using var host = registration
            ? Factory.WithWebHostBuilder(builder =>
                builder.ConfigureTestServices(services =>
                    services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                        new PostConfigureOptions<OidcOptions>(
                            Options.DefaultName,
                            options => options.RequireInitialAccessToken = true))))
            : null;
        var client = host?.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        }) ?? CreateClient();

        var (discovery, request) = await PrepareAsync(client, method, credentials);

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.Unauthorized, $"{(int)response.StatusCode}: {raw}");

        var challenge = ChallengeReader.Parse(Assert.Single(response.Headers.WwwAuthenticate).ToString());
        Assert.Equal(TokenTypes.Bearer, challenge.Scheme);
        Assert.Equal(
            [new KeyValuePair<string, string>(RealmAttribute, discovery.Issuer.OriginalString)],
            challenge.Parameters);
    }

    public static TheoryData<string> Methods() => ["GET", "PUT", "DELETE", "POST"];

    /// <summary>
    /// RFC 6750 section 2.1: the credentials are "Bearer" 1*SP b64token, so the scheme alone is a malformed request,
    /// which section 3.1 names invalid_request ("missing a required parameter ... or is otherwise malformed", "SHOULD
    /// respond with the HTTP 400"), carried on the challenge section 3 requires.
    /// </summary>
    [Theory]
    [MemberData(nameof(Methods))]
    public async Task The_bearer_scheme_without_a_token_is_an_invalid_request(string method)
    {
        var registration = method == HttpMethod.Post.Method;
        await using var host = registration
            ? Factory.WithWebHostBuilder(builder =>
                builder.ConfigureTestServices(services =>
                    services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                        new PostConfigureOptions<OidcOptions>(
                            Options.DefaultName,
                            options => options.RequireInitialAccessToken = true))))
            : null;
        var client = host?.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        }) ?? CreateClient();

        var (_, request) = await PrepareAsync(client, method, BearerSchemeAlone);

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{(int)response.StatusCode}: {raw}");
        Assert.Equal(ErrorCodes.InvalidRequest, JsonNode.Parse(raw)![ErrorResponse.Parameters.Error]!.GetValue<string>());

        var challenge = ChallengeReader.Parse(Assert.Single(response.Headers.WwwAuthenticate).ToString());
        Assert.Equal(TokenTypes.Bearer, challenge.Scheme);
        Assert.Equal(ErrorCodes.InvalidRequest, challenge.Parameters[ErrorResponse.Parameters.Error]);
    }

    private static async Task<(DiscoveryDocument Discovery, HttpRequestMessage Request)> PrepareAsync(
        HttpClient client, string method, string credentials)
    {
        var registration = method == HttpMethod.Post.Method;
        var discovery = await FetchDiscoveryAsync(client);

        Uri target;
        string token;
        JsonObject body;
        if (registration)
        {
            target = discovery.RegistrationEndpoint!;
            token = "any-initial-access-token";
            body = new JsonObject { [RequestMembers.RedirectUris] = new JsonArray(TestConstants.RedirectUri) };
        }
        else
        {
            var registered = await RegisterClientAsync(client, discovery, new JsonObject
            {
                [RequestMembers.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
            });
            target = new Uri(registered[ResponseMembers.RegistrationClientUri]!.GetValue<string>());
            token = registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>();
            body = new JsonObject
            {
                [RequestMembers.ClientId] = registered[ResponseMembers.ClientId]!.GetValue<string>(),
                [RequestMembers.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
            };
        }

        if (credentials == TokenInTheQuery)
            target = new UriBuilder(target) { Query = $"{AccessTokenParameter}={token}" }.Uri;

        var request = new HttpRequestMessage(new HttpMethod(method), target);
        if (method is "PUT" or "POST")
            request.Content = JsonContent.Create(body);

        switch (credentials)
        {
            case NoAuthorization or TokenInTheQuery:
                break;

            case BasicCredentials:
                Assert.True(request.Headers.TryAddWithoutValidation(
                    HttpRequestHeaders.Authorization, $"{TokenTypes.Basic} Y2xpZW50OnNlY3JldA=="));
                break;

            case BasicSchemeAlone:
                Assert.True(request.Headers.TryAddWithoutValidation(HttpRequestHeaders.Authorization, TokenTypes.Basic));
                break;

            case BearerSchemeAlone:
                Assert.True(request.Headers.TryAddWithoutValidation(HttpRequestHeaders.Authorization, TokenTypes.Bearer));
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(credentials), credentials, null);
        }

        return (discovery, request);
    }
}
