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
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 10070 section 4, case B, as a client meets it at the token endpoint, and section 5 at the pushed
/// authorization request endpoint: a client authentication assertion carries the server's issuer identifier as its
/// sole audience, and one naming an endpoint URL - section 4 says the token endpoint URL "MUST NOT be used as an
/// audience value" - or the issuer beside another recipient is refused as from a client that cannot authenticate.
/// </summary>
public class ClientAssertionAudienceTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task AnAssertionNamingTheIssuerAlone_IsIssuedAToken()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await FormPostHelpers.PostFormAsync(
            client, discovery.TokenEndpoint, await FormAsync([discovery.Issuer.OriginalString]));

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.True(response.IsSuccessStatusCode, body.ToJsonString());
        Assert.NotNull(body[TokenResponse.Parameters.AccessToken]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnAssertionNotNamingTheIssuerAlone_IsRefused(bool issuerBesideTheTokenEndpoint)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var tokenEndpoint = discovery.TokenEndpoint.OriginalString;
        string[] audiences = issuerBesideTheTokenEndpoint
            ? [discovery.Issuer.OriginalString, tokenEndpoint]
            : [tokenEndpoint];

        using var response = await FormPostHelpers.PostFormAsync(
            client, discovery.TokenEndpoint, await FormAsync(audiences));

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidClient, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// RFC 9126 section 2 had the server accept "its issuer identifier, token endpoint URL, or pushed authorization
    /// request endpoint URL"; RFC 10070 section 5 replaced that with the issuer alone. So a pushed request whose
    /// assertion names the pushed authorization request endpoint URL is refused as from a client that cannot
    /// authenticate, unless the host granted that client the URL, and the grant does not admit the token endpoint URL.
    /// </summary>
    [Theory]
    [InlineData(TestConstants.PushedAuthorizationRequestAudienceClientId, PushedAuthorizationRequestEndpoint, HttpStatusCode.Created)]
    [InlineData(TestConstants.PushedAuthorizationRequestAudienceClientId, Issuer, HttpStatusCode.Created)]
    [InlineData(TestConstants.PushedAuthorizationRequestAudienceClientId, TokenEndpoint, HttpStatusCode.Unauthorized)]
    [InlineData(TestConstants.ClientSecretJwtClientId, PushedAuthorizationRequestEndpoint, HttpStatusCode.Unauthorized)]
    [InlineData(TestConstants.ClientSecretJwtClientId, Issuer, HttpStatusCode.Created)]
    public async Task APushedRequestsAssertion_NamesItsEndpointOnlyWhereTheHostGrantedIt(
        string clientId, string audience, HttpStatusCode expected)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var pushedAuthorizationRequestEndpoint = discovery.PushedAuthorizationRequestEndpoint!;
        var named = audience switch
        {
            PushedAuthorizationRequestEndpoint => pushedAuthorizationRequestEndpoint.OriginalString,
            Issuer => discovery.Issuer.OriginalString,
            TokenEndpoint => discovery.TokenEndpoint.OriginalString,
            _ => throw new ArgumentOutOfRangeException(nameof(audience), audience, null),
        };
        var (_, challenge) = GeneratePkcePair();
        var form = CodeFlowParameters(clientId, challenge);
        form[ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer;
        form[ClientRequest.Parameters.ClientAssertion] = await ClientSecretJwtAssertion.IssueAsAsync(clientId, named);

        using var response = await FormPostHelpers.PostFormAsync(client, pushedAuthorizationRequestEndpoint, form);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(expected == response.StatusCode, $"{response.StatusCode}: {body}");
        if (expected == HttpStatusCode.Unauthorized)
        {
            Assert.Equal(
                ErrorCodes.InvalidClient,
                JsonNode.Parse(body)![ErrorResponse.Parameters.Error]?.GetValue<string>());
        }
    }

    private const string Issuer = "issuer";
    private const string TokenEndpoint = "token_endpoint";
    private const string PushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint";

    private static async Task<Dictionary<string, string>> FormAsync(string[] audiences)
    {
        return new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer,
            [ClientRequest.Parameters.ClientAssertion] = await ClientSecretJwtAssertion.IssueAsync(audiences),
        };
    }
}
