// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 6749 section 2.3: "The client MUST NOT use more than one authentication method in each request", and section
/// 5.2 names a request that "includes multiple credentials, utilizes more than one mechanism for authenticating the
/// client" an invalid_request, answered with 400. Every endpoint authenticating the client (RFC 7662 section 2.1,
/// RFC 7009 section 2.1, RFC 9126 section 2.1, RFC 8628 section 3.2, OpenID CIBA Core section 7.1) answers each pair of
/// methods so, whichever client the credentials name.
/// </summary>
public class MoreThanOneClientAuthenticationMethodTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// Two client authentication methods used in one request.
    /// </summary>
    public enum MethodPair
    {
        /// <summary>client_secret_basic and client_secret_post.</summary>
        BasicHeaderAndBodySecret,

        /// <summary>A client assertion and client_secret_post.</summary>
        AssertionAndBodySecret,

        /// <summary>client_secret_basic and a client assertion.</summary>
        BasicHeaderAndAssertion,
    }

    public static TheoryData<string, MethodPair> EndpointsAndPairs()
    {
        string[] endpoints =
        [
            nameof(DiscoveryDocument.TokenEndpoint),
            nameof(DiscoveryDocument.IntrospectionEndpoint),
            nameof(DiscoveryDocument.RevocationEndpoint),
            nameof(DiscoveryDocument.PushedAuthorizationRequestEndpoint),
            nameof(DiscoveryDocument.DeviceAuthorizationEndpoint),
            nameof(DiscoveryDocument.BackChannelAuthenticationEndpoint),
        ];

        var data = new TheoryData<string, MethodPair>();
        foreach (var endpoint in endpoints)
        {
            foreach (var pair in Enum.GetValues<MethodPair>())
                data.Add(endpoint, pair);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(EndpointsAndPairs))]
    public async Task Client_authenticating_endpoint_with_two_methods_is_an_invalid_request(
        string endpointName, MethodPair pair)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var endpoint = (Uri?)typeof(DiscoveryDocument).GetProperty(endpointName)!.GetValue(discovery);
        Assert.NotNull(endpoint);

        using var request = await RequestAsync(endpoint, discovery, pair);

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        await AssertInvalidRequestAsync(response);
    }

    /// <summary>
    /// The refusal comes before any credential is checked, so an assertion sent beside a secret is not spent: the same
    /// assertion sent alone afterwards still authenticates the client, where a spent one would be refused as a replay
    /// (RFC 7523 section 3 item 7).
    /// </summary>
    [Fact]
    public async Task Assertion_refused_beside_a_secret_is_not_spent()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var assertion = await ClientSecretJwtAssertion.IssueAsync(discovery.Issuer.OriginalString);

        var form = ClientCredentialsGrant();
        AddAssertion(form, assertion);
        AddBodySecret(form, TestConstants.ClientSecretJwtClientId, TestConstants.ClientSecretJwtSecret);
        using (var refused = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, form))
            await AssertInvalidRequestAsync(refused);

        var alone = ClientCredentialsGrant();
        AddAssertion(alone, assertion);
        using var served = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, alone);
        var raw = await served.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(served.StatusCode == HttpStatusCode.OK, $"{(int)served.StatusCode}: {raw}");
    }

    private static async Task<HttpRequestMessage> RequestAsync(Uri endpoint, DiscoveryDocument discovery, MethodPair pair)
    {
        // Every endpoint's own parameters in one form, valid for the client whose secret is in the body, so a server
        // reading only one of the two credentials serves the request rather than refusing it as invalid_request for
        // a reason of its own
        var form = ClientCredentialsGrant();
        form[IntrospectionRequest.Parameters.Token] = "any";
        form[AuthorizationRequest.Parameters.Scope] = Scopes.OpenId;
        form[AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code;
        form[AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri;
        form[AuthorizationRequest.Parameters.CodeChallenge] = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        form[AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256;

        var basicHeader = false;
        switch (pair)
        {
            case MethodPair.BasicHeaderAndBodySecret:
                basicHeader = true;
                AddBodySecret(form, TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret);
                break;

            case MethodPair.AssertionAndBodySecret:
                AddAssertion(form, await ClientSecretJwtAssertion.IssueAsync(discovery.Issuer.OriginalString));
                AddBodySecret(form, TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret);
                break;

            case MethodPair.BasicHeaderAndAssertion:
                basicHeader = true;
                AddAssertion(form, await ClientSecretJwtAssertion.IssueAsync(discovery.Issuer.OriginalString));
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(pair), pair, null);
        }

        var request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = new FormUrlEncodedContent(form) };
        if (basicHeader)
        {
            var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(
                $"{TestConstants.ClientSecretBasicClientId}:{TestConstants.ConfidentialClientSecret}"));
            Assert.True(request.Headers.TryAddWithoutValidation(
                HttpRequestHeaders.Authorization, $"{TokenTypes.Basic} {credentials}"));
        }

        return request;
    }

    private static Dictionary<string, string> ClientCredentialsGrant()
        => new() { [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials };

    private static void AddAssertion(Dictionary<string, string> form, string assertion)
    {
        form[ClientRequest.Parameters.ClientAssertionType] = ClientAssertionTypes.JwtBearer;
        form[ClientRequest.Parameters.ClientAssertion] = assertion;
    }

    private static void AddBodySecret(Dictionary<string, string> form, string clientId, string secret)
    {
        form[ClientRequest.Parameters.ClientId] = clientId;
        form[ClientRequest.Parameters.ClientSecret] = secret;
    }

    private static async Task AssertInvalidRequestAsync(HttpResponseMessage response)
    {
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{(int)response.StatusCode}: {raw}");
        Assert.Equal(ErrorCodes.InvalidRequest, JsonNode.Parse(raw)![ErrorResponse.Parameters.Error]!.GetValue<string>());
    }
}
