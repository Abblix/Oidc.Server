// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 8707 section 2.2: the server "should downscope the scope value associated with an access token to the value the
/// respective resource is able to process", so an access token carries the scopes of the resources it names, and the
/// token response states the scope the token carries.
/// </summary>
public class ScopePerResourceTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// A grant for two resources, one scope each: the token naming both carries both scopes, and a token narrowed to
    /// one resource carries that resource's scope alone, beside the scopes no resource declares.
    /// </summary>
    [Fact]
    public async Task AnAccessToken_CarriesTheScopesOfTheResourcesItNames()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        string[] granted = [Scopes.OpenId, TestConstants.ApiScope, TestConstants.OtherApiScope];

        var both = await RedeemAsync(client, discovery, await AuthorizeBothAsync(client, discovery, TestConstants.ConfidentialClientId, granted), null);
        var one = await RedeemAsync(
            client,
            discovery,
            await AuthorizeBothAsync(client, discovery, TestConstants.ConfidentialClientId, granted),
            TestConstants.ApiResource);

        AssertAddressed(both, [TestConstants.ApiResource, TestConstants.OtherApiResource], granted);
        AssertAddressed(one, [TestConstants.ApiResource], [Scopes.OpenId, TestConstants.ApiScope]);
    }

    /// <summary>
    /// An authorization code the confidential client is granted for both resources and <paramref name="scope"/>,
    /// with the verifier that redeems it.
    /// </summary>
    private static async Task<(string Code, string Verifier)> AuthorizeBothAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string[] scope)
    {
        var (verifier, challenge) = GeneratePkcePair();
        var code = await AuthorizeAndExtractFromCallbackAsync(
            client,
            discovery,
            [
                .. CodeFlowParameters(clientId, challenge)
                    .Where(parameter => parameter.Key != AuthorizationRequest.Parameters.Scope),
                new(AuthorizationRequest.Parameters.Scope, string.Join(' ', scope)),
                new(AuthorizationRequest.Parameters.Resource, TestConstants.ApiResource),
                new(AuthorizationRequest.Parameters.Resource, TestConstants.OtherApiResource),
            ],
            TokenRequest.Parameters.Code);
        return (code, verifier);
    }

    /// <summary>
    /// A client whose access tokens each name one resource is granted two, and gets a token for each by naming it at
    /// the token endpoint; a token request naming none is refused with <c>invalid_target</c>, and leaves the code to
    /// be redeemed naming one.
    /// </summary>
    [Fact]
    public async Task AClientHeldToOneResource_GetsATokenForEachResourceItNames()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        string[] granted = [Scopes.OpenId, TestConstants.ApiScope, TestConstants.OtherApiScope];
        var first = await AuthorizeBothAsync(client, discovery, TestConstants.SingleResourceClientId, granted);
        var second = await AuthorizeBothAsync(client, discovery, TestConstants.SingleResourceClientId, granted);

        using var refused = await FormPostHelpers.PostFormAsync(
            client,
            discovery.TokenEndpoint,
            RedeemForm(TestConstants.SingleResourceClientId, first, null));
        var refusal = JsonNode.Parse(await refused.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        var orders = await ExchangeCodeForTokensAsync(
            client,
            discovery,
            RedeemForm(TestConstants.SingleResourceClientId, first, TestConstants.ApiResource));
        var payments = await ExchangeCodeForTokensAsync(
            client,
            discovery,
            RedeemForm(TestConstants.SingleResourceClientId, second, TestConstants.OtherApiResource));

        Assert.Equal(ErrorCodes.InvalidTarget, refusal[ResponseParameters.Error]?.GetValue<string>());
        AssertAddressed(orders, [TestConstants.ApiResource], [Scopes.OpenId, TestConstants.ApiScope]);
        AssertAddressed(payments, [TestConstants.OtherApiResource], [Scopes.OpenId, TestConstants.OtherApiScope]);
    }

    /// <summary>
    /// The token response to redeeming <paramref name="grant"/>, naming <paramref name="resource"/> when it is given.
    /// </summary>
    private static Task<JsonObject> RedeemAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        (string Code, string Verifier) grant,
        string? resource)
        => ExchangeCodeForTokensAsync(client, discovery, RedeemForm(TestConstants.ConfidentialClientId, grant, resource));

    /// <summary>
    /// The token request redeeming <paramref name="grant"/> as <paramref name="clientId"/>, naming
    /// <paramref name="resource"/> when it is given.
    /// </summary>
    private static Dictionary<string, string> RedeemForm(
        string clientId,
        (string Code, string Verifier) grant,
        string? resource)
    {
        var form = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = grant.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = grant.Verifier,
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        };
        if (resource is not null)
            form[TokenRequest.Parameters.Resource] = resource;

        return form;
    }

    /// <summary>
    /// The access token in <paramref name="response"/> names <paramref name="resources"/> and carries
    /// <paramref name="scope"/>, and the response states that scope.
    /// </summary>
    private static void AssertAddressed(JsonObject response, string[] resources, string[] scope)
    {
        var payload = DecodeJwtPayload(response[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());

        Assert.Equal(resources.Order(), ExtractAudiences(payload).Order());
        Assert.Equal(scope.Order(), payload[IanaClaimTypes.Scope]!.GetValue<string>().Split(' ').Order());
        Assert.Equal(scope.Order(), response[TokenRequest.Parameters.Scope]!.GetValue<string>().Split(' ').Order());
    }
}
