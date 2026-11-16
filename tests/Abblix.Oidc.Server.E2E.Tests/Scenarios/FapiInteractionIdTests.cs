// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// FAPI 1.0 Part 1 section 6.2.1: the protected resource "shall set the response header x-fapi-interaction-id to the
/// value received from the corresponding FAPI client request header or to a RFC4122 UUID value if the request header was
/// not provided". UserInfo answers so for a client held to FAPI 1.0 Advanced on both hosts, which carry no code of
/// their own for it, and leaves the header out for a client under no profile.
/// </summary>
public class FapiInteractionIdTests(TestFactory factory) : TestBase(factory)
{
    private const string FapiClientId = "e2e-fapi1-interaction-id";
    private const string PlainClientId = "e2e-no-profile-interaction-id";
    private const string ClientValue = "c770aef3-6784-41f7-8e0e-ff5f97bddb3a";
    private const string OtherClientValue = "0e4f2a9c-5b7d-4c1e-9f3a-2d6b8e1c7a40";

    [Fact]
    public async Task TheClientsValue_IsEchoed()
    {
        using var response = await UserInfoAsync(ClientSecurityProfile.Fapi1Advanced, FapiClientId, ClientValue);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(ClientValue, Assert.Single(InteractionIdsOf(response)));
    }

    /// <summary>
    /// No header, a value that is no UUID, and a repeated header are all answered with a UUID of the server's own.
    /// </summary>
    [Theory]
    [InlineData()]
    [InlineData("not-a-uuid")]
    [InlineData(ClientValue, OtherClientValue)]
    public async Task WithoutOneUuidFromTheClient_AUuidOfTheServersOwn_IsSet(params string[] received)
    {
        using var response = await UserInfoAsync(ClientSecurityProfile.Fapi1Advanced, FapiClientId, received);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var answered = Assert.Single(InteractionIdsOf(response));
        Assert.True(Guid.TryParseExact(answered, "D", out _), answered);
        Assert.DoesNotContain(answered, received);
    }

    /// <summary>
    /// The negative control: FAPI 1.0 binds the header on its own clients, and a client under no profile gets none.
    /// </summary>
    [Fact]
    public async Task AClientUnderNoProfile_GetsNoHeader()
    {
        using var response = await UserInfoAsync(null, PlainClientId, ClientValue);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Empty(InteractionIdsOf(response));
    }

    /// <summary>
    /// The header goes on the resource's refusals too: a token the server issued to a client of FAPI 1.0 Advanced at a
    /// tenant holding its clients to no profile, refused once read for lacking the openid scope, is answered with the
    /// client's value.
    /// </summary>
    [Fact]
    public async Task ARefusalAfterTheTokenNamedTheClient_EchoesTheClientsValue()
    {
        using var response = await UserInfoAsync(
            ClientSecurityProfile.Fapi1Advanced, FapiClientId, [Scopes.Profile], ClientValue);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(ClientValue, Assert.Single(InteractionIdsOf(response)));
    }

    /// <summary>
    /// The negative control of the refusal above: the same refusal for a client under no profile carries no header.
    /// </summary>
    [Fact]
    public async Task ARefusalForAClientUnderNoProfile_GetsNoHeader()
    {
        using var response = await UserInfoAsync(null, PlainClientId, [Scopes.Profile], ClientValue);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(InteractionIdsOf(response));
    }

    private static IEnumerable<string> InteractionIdsOf(HttpResponseMessage response)
        => response.Headers.TryGetValues(HttpRequestHeaders.FapiInteractionId, out var values) ? values : [];

    /// <summary>
    /// Calls UserInfo with an access token the server issued to a client of <paramref name="profile"/>, sending each of
    /// <paramref name="interactionIds"/> as the request header.
    /// </summary>
    private Task<HttpResponseMessage> UserInfoAsync(
        ClientSecurityProfile? profile, string clientId, params string[] interactionIds)
        => UserInfoAsync(profile, clientId, [Scopes.OpenId], interactionIds);

    /// <summary>
    /// Calls UserInfo with an access token for <paramref name="scope"/> the server issued to a client of
    /// <paramref name="profile"/>, sending each of <paramref name="interactionIds"/> as the request header.
    /// </summary>
    private async Task<HttpResponseMessage> UserInfoAsync(
        ClientSecurityProfile? profile, string clientId, string[] scope, params string[] interactionIds)
    {
        await using var host = HostSigningAccessTokensWithPs256();
        var services = host.Services;
        var tenant = TestTenant.Of(services);
        var clientInfo = new ClientInfo(clientId) { SecurityProfile = profile };
        string accessToken;
        using (TestTenant.Enter(services))
        {
            Assert.True(await services.GetRequiredService<IClientInfoManager>()
                .TryAddClientAsync(tenant, new RegisteredClient(clientInfo, $"{clientId}-registration")));

            var issued = await services.GetRequiredService<IAccessTokenService>().CreateAccessTokenAsync(
                tenant,
                new AuthSession("user-1", "session-1", services.GetRequiredService<TimeProvider>().GetUtcNow(), "local"),
                new AuthorizationContext(clientId, scope, requestedClaims: null),
                clientInfo,
                grantId: null,
                expiresNoLaterThan: null);
            accessToken = issued.EncodedJwt;
        }

        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        var discovery = await FetchDiscoveryAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);
        if (interactionIds.Length > 0)
            request.Headers.Add(HttpRequestHeaders.FapiInteractionId, interactionIds);

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        await response.Content.LoadIntoBufferAsync(TestContext.Current.CancellationToken);
        return response;
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 8.6 holds what the server signs for a client of that profile to PS256 or ES256, the
    /// access token among them.
    /// </summary>
    private WebApplicationFactory<Program> HostSigningAccessTokensWithPs256()
        => Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ => new PostConfigureOptions<OidcOptions>(
                Options.DefaultName,
                options => options.ServiceTokens.AccessToken.Signing.Algorithm = SigningAlgorithms.PS256))));
}
