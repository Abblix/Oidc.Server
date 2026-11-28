// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// An authorization code is spent only once tokens are issued for it: a request refused while its token is issued -
/// for a resource the token cannot be encrypted to - leaves the code for the corrected request, a code tokens were
/// issued for is refused the next time, and of requests redeeming one code at once exactly one is issued tokens.
/// </summary>
public class AuthorizationCodeRedemptionTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// A code granted for two resources, one of which publishes only a key no token can be encrypted to, is refused as
    /// an invalid target when redeemed for both, then redeemed for the other one, and refused once tokens were issued.
    /// </summary>
    [Fact]
    public async Task A_code_refused_a_resource_its_token_cannot_be_encrypted_to_is_redeemed_for_another()
    {
        await using var host = CreateHostWhereTheApiPublishesASigningKey();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var (code, verifier) = await AuthorizeForBothResourcesAsync(client, discovery);

        using var refused = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, RedeemForm(code, verifier));
        await AssertRefusedAsync(refused, ErrorCodes.InvalidTarget);

        using var granted = await FormPostHelpers.PostFormAsync(
            client,
            discovery.TokenEndpoint,
            [.. RedeemForm(code, verifier), new(TokenRequest.Parameters.Resource, TestConstants.OtherApiResource)]);
        Assert.True(granted.StatusCode == HttpStatusCode.OK, await granted.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        using var reused = await FormPostHelpers.PostFormAsync(
            client,
            discovery.TokenEndpoint,
            [.. RedeemForm(code, verifier), new(TokenRequest.Parameters.Resource, TestConstants.OtherApiResource)]);
        await AssertRefusedAsync(reused, ErrorCodes.InvalidGrant);
    }

    /// <summary>
    /// Requests redeeming one code at once, each of which would be issued tokens alone, are issued exactly one set:
    /// the others are refused as an invalid grant.
    /// </summary>
    [Fact]
    public async Task A_code_redeemed_by_concurrent_requests_is_redeemed_once()
    {
        const int requests = 8;
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (verifier, challenge) = GeneratePkcePair();
        var code = await AuthorizeAndExtractCodeAsync(
            client, discovery, CodeFlowParameters(TestConstants.ConfidentialClientId, challenge));

        var responses = await Task.WhenAll(Enumerable.Range(0, requests)
            .Select(_ => FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, RedeemForm(code, verifier))));
        try
        {
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.OK);
            foreach (var response in responses.Where(response => response.StatusCode != HttpStatusCode.OK))
                await AssertRefusedAsync(response, ErrorCodes.InvalidGrant);
        }
        finally
        {
            foreach (var response in responses)
                response.Dispose();
        }
    }

    /// <summary>
    /// The test host with its API resource publishing one key, declaring a signing algorithm, so a token addressed to
    /// it cannot be encrypted to it.
    /// </summary>
    private WebApplicationFactory<Program> CreateHostWhereTheApiPublishesASigningKey()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);
        key.Algorithm = SigningAlgorithms.RS256;
        return Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.PostConfigure<TestTenantSettings>(tenant => tenant.Resources =
                [
                    new ResourceDefinition(new Uri(TestConstants.ApiResource), new ScopeDefinition(TestConstants.ApiScope))
                    {
                        Jwks = new JsonWebKeySet([key.Sanitize(includePrivateKeys: false)]),
                    },
                    new ResourceDefinition(
                        new Uri(TestConstants.OtherApiResource),
                        new ScopeDefinition(TestConstants.OtherApiScope)),
                ])));
    }

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    private static async Task<(string Code, string Verifier)> AuthorizeForBothResourcesAsync(
        HttpClient client,
        DiscoveryDocument discovery)
    {
        var (verifier, challenge) = GeneratePkcePair();
        var code = await AuthorizeAndExtractFromCallbackAsync(
            client,
            discovery,
            [
                .. CodeFlowParameters(TestConstants.ConfidentialClientId, challenge),
                new(AuthorizationRequest.Parameters.Resource, TestConstants.ApiResource),
                new(AuthorizationRequest.Parameters.Resource, TestConstants.OtherApiResource),
            ],
            ResponseParameters.Code);
        return (code, verifier);
    }

    private static KeyValuePair<string, string>[] RedeemForm(string code, string verifier) =>
    [
        new(TokenRequest.Parameters.GrantType, GrantTypes.AuthorizationCode),
        new(TokenRequest.Parameters.Code, code),
        new(TokenRequest.Parameters.RedirectUri, TestConstants.RedirectUri),
        new(TokenRequest.Parameters.CodeVerifier, verifier),
        new(ClientRequest.Parameters.ClientId, TestConstants.ConfidentialClientId),
        new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
    ];

    private static async Task AssertRefusedAsync(HttpResponseMessage response, string error)
    {
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"expected 400, got {(int)response.StatusCode}: {body}");
        Assert.Equal(error, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }
}
