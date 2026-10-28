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
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Model;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A token request naming a resource its grant does not hold is refused with <c>invalid_target</c>, whatever else it
/// names and whether the grant holds resources or none, and the refusal leaves an authorization code redeemable.
/// </summary>
public class ResourceOutsideTheGrantTests(TestFactory factory) : TestBase(factory)
{
    private const string Code = "code";
    private const string Refresh = "refresh";

    /// <summary>
    /// A grant issued for one resource refuses a request naming another, alone or beside the granted one, rather than
    /// issuing a token that leaves it out (RFC 8707 section 2.2).
    /// </summary>
    [Theory]
    [InlineData(Code, false)]
    [InlineData(Code, true)]
    [InlineData(Refresh, false)]
    [InlineData(Refresh, true)]
    public async Task A_request_naming_a_resource_outside_its_grant_is_refused(string redeemed, bool alsoNamesTheGranted)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        string[] named = alsoNamesTheGranted
            ? [TestConstants.ApiResource, TestConstants.OtherApiResource]
            : [TestConstants.OtherApiResource];

        using var response = await RedeemNamingAsync(client, discovery, redeemed, grantedResource: TestConstants.ApiResource, named);

        await AssertRefusedAsync(response, ErrorCodes.InvalidTarget);
    }

    /// <summary>
    /// A grant issued for no resource refuses a request naming one, rather than issuing a token addressed elsewhere.
    /// </summary>
    [Theory]
    [InlineData(Code)]
    [InlineData(Refresh)]
    public async Task A_request_naming_a_resource_for_a_grant_holding_none_is_refused(string redeemed)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await RedeemNamingAsync(client, discovery, redeemed, grantedResource: null, [TestConstants.ApiResource]);

        await AssertRefusedAsync(response, ErrorCodes.InvalidTarget);
    }

    /// <summary>
    /// A code redemption refused for reaching outside its grant, for a resource or for a scope, does not spend the code:
    /// the client corrects the request and redeems it.
    /// </summary>
    [Theory]
    [InlineData(TokenRequest.Parameters.Resource, TestConstants.OtherApiResource, ErrorCodes.InvalidTarget)]
    [InlineData(TokenRequest.Parameters.Scope, Scopes.Profile, ErrorCodes.InvalidScope)]
    public async Task A_code_refused_for_reaching_outside_its_grant_stays_redeemable(
        string parameter,
        string outside,
        string error)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (code, verifier) = await AuthorizeAsync(client, discovery, TestConstants.ConfidentialClientId, TestConstants.ApiResource);

        using var refused = await FormPostHelpers.PostFormAsync(
            client,
            discovery.TokenEndpoint,
            [.. RedeemForm(TestConstants.ConfidentialClientId, code, verifier), new(parameter, outside)]);
        await AssertRefusedAsync(refused, error);

        var tokens = await ExchangeCodeForTokensAsync(
            client,
            discovery,
            RedeemForm(TestConstants.ConfidentialClientId, code, verifier).ToDictionary());

        Assert.Equal([TestConstants.ApiResource], ExtractAudiences(DecodeJwtPayload(tokens[ResponseParameters.AccessToken]!.GetValue<string>())));
    }

    /// <summary>
    /// A client whose access tokens each name one resource is told a resource outside its grant was not granted,
    /// rather than that it named too many.
    /// </summary>
    [Fact]
    public async Task A_client_held_to_one_resource_is_told_the_resource_was_not_granted()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (code, verifier) = await AuthorizeAsync(client, discovery, TestConstants.SingleResourceClientId, TestConstants.ApiResource);

        using var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.TokenEndpoint,
            [
                .. RedeemForm(TestConstants.SingleResourceClientId, code, verifier),
                new(TokenRequest.Parameters.Resource, TestConstants.ApiResource),
                new(TokenRequest.Parameters.Resource, TestConstants.OtherApiResource),
            ]);
        var body = await AssertRefusedAsync(response, ErrorCodes.InvalidTarget);

        Assert.Equal(ResourceRefusals.NotGranted, body[ResponseParameters.ErrorDescription]?.GetValue<string>());
    }

    private static async Task<HttpResponseMessage> RedeemNamingAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string redeemed,
        string? grantedResource,
        string[] named)
    {
        var (code, verifier) = await AuthorizeAsync(client, discovery, TestConstants.ConfidentialClientId, grantedResource);
        var resources = named.Select(resource => new KeyValuePair<string, string>(TokenRequest.Parameters.Resource, resource));

        switch (redeemed)
        {
            case Code:
                return await FormPostHelpers.PostFormAsync(
                    client,
                    discovery.TokenEndpoint,
                    [.. RedeemForm(TestConstants.ConfidentialClientId, code, verifier), .. resources]);

            case Refresh:
                var tokens = await ExchangeCodeForTokensAsync(
                    client,
                    discovery,
                    RedeemForm(TestConstants.ConfidentialClientId, code, verifier).ToDictionary());
                return await FormPostHelpers.PostFormAsync(
                    client,
                    discovery.TokenEndpoint,
                    [
                        new(TokenRequest.Parameters.GrantType, GrantTypes.RefreshToken),
                        new(TokenRequest.Parameters.RefreshToken, tokens[TokenRequest.Parameters.RefreshToken]!.GetValue<string>()),
                        new(AuthorizationRequest.Parameters.ClientId, TestConstants.ConfidentialClientId),
                        new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
                        .. resources,
                    ]);

            default:
                throw new ArgumentOutOfRangeException(nameof(redeemed), redeemed, null);
        }
    }

    private static async Task<(string Code, string Verifier)> AuthorizeAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string? resource)
    {
        var (verifier, challenge) = GeneratePkcePair();
        var parameters = CodeFlowParameters(clientId, challenge);
        parameters[AuthorizationRequest.Parameters.Scope] = $"{Scopes.OpenId} {Scopes.OfflineAccess}";
        if (resource is not null)
            parameters[AuthorizationRequest.Parameters.Resource] = resource;

        return (await AuthorizeAndExtractCodeAsync(client, discovery, parameters), verifier);
    }

    private static KeyValuePair<string, string>[] RedeemForm(string clientId, string code, string verifier) =>
    [
        new(TokenRequest.Parameters.GrantType, GrantTypes.AuthorizationCode),
        new(TokenRequest.Parameters.Code, code),
        new(AuthorizationRequest.Parameters.RedirectUri, TestConstants.RedirectUri),
        new(TokenRequest.Parameters.CodeVerifier, verifier),
        new(AuthorizationRequest.Parameters.ClientId, clientId),
        new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
    ];

    private static async Task<JsonObject> AssertRefusedAsync(HttpResponseMessage response, string error)
    {
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"expected 400 {error}, got {(int)response.StatusCode}: {body}");
        Assert.Equal(error, body[ResponseParameters.Error]?.GetValue<string>());
        return body;
    }
}
