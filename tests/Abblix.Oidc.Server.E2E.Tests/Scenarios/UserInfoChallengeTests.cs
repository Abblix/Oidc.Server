// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.MinimalApi.UnitTests;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// Which of the two challenges a UserInfo refusal advertises carries the error, driven through both hosts and read by
/// the challenge grammar. RFC 9449 section 7.2: "If no authentication information has been included with the request,
/// then the challenges SHOULD NOT include an error code or other error information"; "If the mechanism used to attempt
/// authentication could be established unambiguously, then the corresponding challenge SHOULD be used to deliver error
/// information"; "Otherwise, both Bearer and DPoP challenges MAY be used to deliver error information".
/// </summary>
/// <remarks>
/// Every row reads both challenges, the one that must carry the error and the one that must not, since a refusal
/// stamped with no scheme puts the error on both and only the second half of a row tells that apart.
/// </remarks>
public class UserInfoChallengeTests(TestFactory factory) : DPoPTestBase(factory)
{
    private const string Error = "error";
    private const string ErrorDescription = "error_description";
    private const string Scope = "scope";
    private const string Algorithms = "algs";

    /// <summary>
    /// RFC 6750 section 3.1 and RFC 9449 section 7.2, Figure 17: no credentials, two bare challenges, the DPoP one still
    /// naming its algorithms.
    /// </summary>
    [Fact]
    public async Task A_request_without_credentials_gets_bare_challenges()
    {
        var (client, discovery) = await EndpointAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var (dpop, bearer) = Challenges(response);
        Assert.DoesNotContain(Error, dpop.Parameters.Keys);
        Assert.Contains(Algorithms, dpop.Parameters.Keys);
        Assert.DoesNotContain(Error, bearer.Parameters.Keys);
    }

    /// <summary>
    /// RFC 9449 section 7.2, Figure 18: <c>Authorization: Bearer INVALID_TOKEN</c> gets the error on the Bearer
    /// challenge.
    /// </summary>
    [Fact]
    public async Task A_bearer_header_failure_carries_the_error_on_the_bearer_challenge()
    {
        var (client, discovery) = await EndpointAsync();

        var response = await SendAsync(client, discovery, TokenTypes.Bearer, "INVALID_TOKEN", proof: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var (dpop, bearer) = Challenges(response);
        Assert.Equal(ErrorCodes.InvalidToken, bearer.Parameters[Error]);
        Assert.Contains(ErrorDescription, bearer.Parameters.Keys);
        Assert.DoesNotContain(Error, dpop.Parameters.Keys);
        Assert.DoesNotContain(ErrorDescription, dpop.Parameters.Keys);
    }

    /// <summary>
    /// RFC 6750 section 2.2 is a method of sending a bearer access token, so a refused <c>access_token</c> in the body
    /// is a Bearer failure too.
    /// </summary>
    [Fact]
    public async Task A_bearer_token_in_the_body_failure_carries_the_error_on_the_bearer_challenge()
    {
        var (client, discovery) = await EndpointAsync();

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.UserInfoEndpoint)
        {
            Content = new FormUrlEncodedContent(
                new Dictionary<string, string> { [UserInfoRequest.Parameters.AccessToken] = "INVALID_TOKEN" }),
        };
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var (dpop, bearer) = Challenges(response);
        Assert.Equal(ErrorCodes.InvalidToken, bearer.Parameters[Error]);
        Assert.DoesNotContain(Error, dpop.Parameters.Keys);
    }

    /// <summary>
    /// A DPoP-bound token whose proof is signed by another key fails over DPoP: the error goes on the DPoP challenge.
    /// </summary>
    [Fact]
    public async Task A_dpop_failure_carries_the_error_on_the_dpop_challenge()
    {
        using var bindingKey = new DPoPProofGenerator();
        using var attackerKey = new DPoPProofGenerator();
        var (client, discovery) = await EndpointAsync();
        var accessToken = await ObtainBoundTokenAsync(client, discovery, bindingKey);

        var proof = attackerKey.BuildProof(HttpMethods.Get, discovery.UserInfoEndpoint!, accessToken: accessToken);
        var response = await SendAsync(client, discovery, TokenTypes.DPoP, accessToken, proof);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var (dpop, bearer) = Challenges(response);
        Assert.Equal(ErrorCodes.InvalidDPoPProof, dpop.Parameters[Error]);
        Assert.Contains(Algorithms, dpop.Parameters.Keys);
        Assert.DoesNotContain(Error, bearer.Parameters.Keys);
        Assert.DoesNotContain(ErrorDescription, bearer.Parameters.Keys);
    }

    /// <summary>
    /// A DPoP-bound token sent with the Bearer scheme is refused once the token names its client (RFC 9449 section
    /// 7.2: "such a protected resource MUST reject a DPoP-bound access token received as a bearer token"). The client
    /// used Bearer, so the Bearer challenge carries the error, and the DPoP one beside it says which scheme to switch to.
    /// </summary>
    [Fact]
    public async Task A_bound_token_sent_as_bearer_carries_the_error_on_the_bearer_challenge()
    {
        using var proofKey = new DPoPProofGenerator();
        var (client, discovery) = await EndpointAsync();
        var accessToken = await ObtainBoundTokenAsync(client, discovery, proofKey);

        var response = await SendAsync(client, discovery, TokenTypes.Bearer, accessToken, proof: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var (dpop, bearer) = Challenges(response);
        Assert.Equal(ErrorCodes.InvalidToken, bearer.Parameters[Error]);
        Assert.DoesNotContain(Error, dpop.Parameters.Keys);
        Assert.Contains(Algorithms, dpop.Parameters.Keys);
    }

    /// <summary>
    /// RFC 6750 section 3.1: insufficient_scope "MAY include the "scope" attribute with the scope necessary to access
    /// the protected resource", which for UserInfo is openid (OpenID Connect Core 1.0 section 5.3).
    /// </summary>
    [Fact]
    public async Task A_token_without_openid_names_the_scope_on_the_bearer_challenge()
    {
        var (client, discovery) = await EndpointAsync();
        var tokenResponse = await DriveParAuthorizeTokenAsync(
            client, discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null, tokenProof: null,
            scope: Scopes.Profile);
        var accessToken = tokenResponse[TokenResponse.Parameters.AccessToken]!.GetValue<string>();

        var response = await SendAsync(client, discovery, TokenTypes.Bearer, accessToken, proof: null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var (dpop, bearer) = Challenges(response);
        Assert.Equal(ErrorCodes.InsufficientScope, bearer.Parameters[Error]);
        Assert.Equal(Scopes.OpenId, bearer.Parameters[Scope]);
        Assert.DoesNotContain(Error, dpop.Parameters.Keys);
        Assert.DoesNotContain(Scope, dpop.Parameters.Keys);
    }

    /// <summary>
    /// RFC 9449 section 7.2, Figure 19: a DPoP header beside an <c>access_token</c> parameter names two schemes at
    /// once, so the mechanism cannot be established and both challenges carry the invalid_request.
    /// </summary>
    [Fact]
    public async Task Two_schemes_at_once_carry_the_error_on_both_challenges()
    {
        var (client, discovery) = await EndpointAsync();

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.UserInfoEndpoint)
        {
            Content = new FormUrlEncodedContent(
                new Dictionary<string, string> { [UserInfoRequest.Parameters.AccessToken] = "TOKEN" }),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.DPoP, "TOKEN");
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var (dpop, bearer) = Challenges(response);
        Assert.Equal(ErrorCodes.InvalidRequest, dpop.Parameters[Error]);
        Assert.Equal(ErrorCodes.InvalidRequest, bearer.Parameters[Error]);
    }

    private async Task<(HttpClient Client, DiscoveryDocument Discovery)> EndpointAsync()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.UserInfoEndpoint);
        return (client, discovery);
    }

    private static async Task<string> ObtainBoundTokenAsync(
        HttpClient client, DiscoveryDocument discovery, DPoPProofGenerator proofKey)
    {
        var tokenResponse = await DriveParAuthorizeTokenAsync(
            client, discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null, tokenProof: proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint));
        AssertDPoPBound(tokenResponse, expectedThumbprint: proofKey.Thumbprint);
        return tokenResponse[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
    }

    private static async Task<HttpResponseMessage> SendAsync(
        HttpClient client, DiscoveryDocument discovery, string scheme, string accessToken, string? proof)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(scheme, accessToken);
        if (proof is not null)
            request.WithDPoPHeader(proof);
        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// The DPoP and the Bearer challenge of the response, each exactly once.
    /// </summary>
    private static (ChallengeReader.Challenge DPoP, ChallengeReader.Challenge Bearer) Challenges(
        HttpResponseMessage response)
    {
        var challenges = response.Headers.WwwAuthenticate
            .Select(header => ChallengeReader.Parse(header.ToString()))
            .ToArray();

        Assert.Equal(2, challenges.Length);
        return (
            Assert.Single(challenges, challenge => challenge.Scheme == TokenTypes.DPoP),
            Assert.Single(challenges, challenge => challenge.Scheme == TokenTypes.Bearer));
    }
}
