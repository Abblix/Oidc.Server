// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;
using CodeResponse = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A token request whose scopes all fall away when the token is narrowed to the resource it names. RFC 6749 section
/// 5.1 lets an absent scope in the response mean "as requested", so a client that named scopes is refused with
/// invalid_scope (section 5.2), while a client that named none, and was served its default, asked for nothing and
/// is issued a token with no scope.
/// </summary>
/// <remarks>
/// The client's default scope is one only the first resource declares; the grant holds both resources, and the
/// token is asked for the second one, so narrowing leaves the token no scope either way. Each case runs sent by value
/// and pushed, since a pushed request is validated, stored and read back before the code is issued, and whether the
/// client named a scope has to survive that.
/// </remarks>
public class ScopeNarrowedAwayTests(TestFactory factory) : TestBase(factory)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ADefaultScopeTheClientNeverNamed_NarrowedAway_IsIssuedATokenWithNoScope(bool pushed)
    {
        var response = await RedeemForTheOtherResourceAsync(namesScope: false, pushed);

        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, raw);
        Assert.False(JsonNode.Parse(raw)!.AsObject().ContainsKey(TokenResponse.Parameters.Scope));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TheSameScopeNamedByTheClient_NarrowedAway_IsRefusedWithInvalidScope(bool pushed)
    {
        var response = await RedeemForTheOtherResourceAsync(namesScope: true, pushed);

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidScope, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    private async Task<HttpResponseMessage> RedeemForTheOtherResourceAsync(bool namesScope, bool pushed)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (verifier, challenge) = GeneratePkcePair();

        var parameters = CodeFlowParameters(TestConstants.DefaultScopeCodeClientId, challenge);
        if (namesScope)
            parameters[AuthorizationRequest.Parameters.Scope] = TestConstants.ApiScope;
        else
            parameters.Remove(AuthorizationRequest.Parameters.Scope);

        List<KeyValuePair<string, string>> request =
        [
            .. parameters,
            new(AuthorizationRequest.Parameters.Resource, TestConstants.ApiResource),
            new(AuthorizationRequest.Parameters.Resource, TestConstants.OtherApiResource),
        ];

        if (pushed)
        {
            var pushResponse = await PushAuthorizationRequestAsync(client, discovery,
            [
                .. request,
                new(ClientRequest.Parameters.ClientSecret, TestConstants.ConfidentialClientSecret),
            ]);
            request =
            [
                new(AuthorizationRequest.Parameters.ClientId, TestConstants.DefaultScopeCodeClientId),
                new(AuthorizationRequest.Parameters.RequestUri,
                    pushResponse[PushedAuthorizationResponse.Parameters.RequestUri]!.GetValue<string>()),
            ];
        }

        var code = await AuthorizeAndExtractFromCallbackAsync(client, discovery, request, CodeResponse.Parameters.Code);

        return await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [TokenRequest.Parameters.Resource] = TestConstants.OtherApiResource,
            [ClientRequest.Parameters.ClientId] = TestConstants.DefaultScopeCodeClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });
    }
}
