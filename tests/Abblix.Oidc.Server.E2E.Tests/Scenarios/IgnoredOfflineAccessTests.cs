// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using CodeResponse = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// An offline_access the server ignores is as if never asked for (OpenID Connect Core 1.0 section 11), so a request
/// naming it alone named no scope and is served the client's default, for the resource that default belongs to - sent
/// by value and pushed alike, since a pushed request is validated, stored and read back before the code is issued.
/// </summary>
/// <remarks>
/// The client receives offline access only when the request asks for consent, which this one does not, and its
/// default scope is one only <see cref="TestConstants.ApiResource"/> declares, so the resources settled for the
/// request and the scope it is served have to agree for it to pass at all: whether the request names that resource
/// or the tenant infers it from the scope.
/// </remarks>
public class IgnoredOfflineAccessTests(TestFactory factory) : TestBase(factory)
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task OfflineAccessAloneAndIgnored_IsServedTheClientsDefaultForItsResource(bool pushed, bool inferred)
    {
        await using var host = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<TestTenantSettings>>(_ =>
                    new PostConfigureOptions<TestTenantSettings>(
                        Options.DefaultName,
                        tenant => tenant.InferResourceFromScope = inferred))));
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var (verifier, challenge) = GeneratePkcePair();

        var parameters = CodeFlowParameters(TestConstants.DefaultScopeCodeClientId, challenge);
        parameters[AuthorizationRequest.Parameters.Scope] = Scopes.OfflineAccess;
        if (!inferred)
            parameters[AuthorizationRequest.Parameters.Resource] = TestConstants.ApiResource;
        List<KeyValuePair<string, string>> request = [.. parameters];

        if (pushed)
        {
            var pushResponse = await PushAuthorizationRequestAsync(client, discovery,
            [
                .. request,
                new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
            ]);
            var requestUri = pushResponse[PushedAuthorizationResponse.Parameters.RequestUri]?.GetValue<string>();
            Assert.NotNull(requestUri);
            request =
            [
                new(AuthorizationRequest.Parameters.ClientId, TestConstants.DefaultScopeCodeClientId),
                new(AuthorizationRequest.Parameters.RequestUri, requestUri),
            ];
        }

        var code = await AuthorizeAndExtractFromCallbackAsync(client, discovery, request, CodeResponse.Parameters.Code);
        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [ClientRequest.Parameters.ClientId] = TestConstants.DefaultScopeCodeClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var accessToken = tokens[TokenResponse.Parameters.AccessToken]?.GetValue<string>();
        Assert.NotNull(accessToken);
        var payload = DecodeJwtPayload(accessToken);
        Assert.Equal(TestConstants.ApiScope, payload[IanaClaimTypes.Scope]?.GetValue<string>());
        Assert.Equal(TestConstants.ApiResource, payload[IanaClaimTypes.Aud]?.ToString());
        Assert.False(tokens.ContainsKey(TokenResponse.Parameters.RefreshToken));
    }

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
}
