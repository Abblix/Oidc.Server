// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <remarks>
/// The client_id rules of a pushed authorization request and of a request object, pinned on both sides of each
/// exemption, so a repair wider than the clause that justifies it fails a row.
/// </remarks>
public partial class JarRichAuthorizationRequestsTests
{
    /// <summary>Which client a value names: the one that authenticated, another one, or none.</summary>
    public enum Named
    {
        Nobody,
        Poster,
        Other,
    }

    /// <summary>
    /// RFC 9126 section 2.1 requires client_id in a pushed request; section 3 exempts only a form carrying "request",
    /// whose step 3 compares the authenticated client with "the "client_id" claim in the Request Object".
    /// </summary>
    [Theory]
    // Section 2.1: client_id "is similarly required in a pushed authorization request"
    [InlineData(false, Named.Nobody, false, Named.Nobody, Named.Nobody, HttpStatusCode.BadRequest, ErrorCodes.UnauthorizedClient)]
    // Section 2.1: the authenticated client naming itself
    [InlineData(false, Named.Poster, false, Named.Nobody, Named.Nobody, HttpStatusCode.Created, null)]
    // Section 2.1: a client_id of another client than the one that authenticated
    [InlineData(false, Named.Other, false, Named.Nobody, Named.Nobody, HttpStatusCode.BadRequest, ErrorCodes.InvalidRequest)]
    // Section 3: the object alone, naming the authenticated client
    [InlineData(false, Named.Nobody, true, Named.Poster, Named.Poster, HttpStatusCode.Created, null)]
    // Section 3 step 3: the object alone, signed with the authenticated client's key, naming another client
    [InlineData(false, Named.Nobody, true, Named.Other, Named.Poster, HttpStatusCode.BadRequest, ErrorCodes.InvalidRequestObject)]
    // Section 3 step 3: the object alone, another client's own
    [InlineData(false, Named.Nobody, true, Named.Other, Named.Other, HttpStatusCode.BadRequest, ErrorCodes.InvalidRequestObject)]
    // Section 3 step 3: the object alone naming no client, merged over the outer parameters
    [InlineData(false, Named.Nobody, true, Named.Nobody, Named.Poster, HttpStatusCode.BadRequest, ErrorCodes.InvalidRequestObject)]
    // Section 3 step 3: the object alone naming no client, processed strictly
    [InlineData(true, Named.Nobody, true, Named.Nobody, Named.Poster, HttpStatusCode.BadRequest, ErrorCodes.InvalidRequestObject)]
    // Section 3: the object beside a client_id of another client than the one that authenticated
    [InlineData(false, Named.Other, true, Named.Poster, Named.Poster, HttpStatusCode.BadRequest, ErrorCodes.InvalidRequest)]
    public async Task APushedRequest_IsAcceptedOnlyForTheClientThatAuthenticated(
        bool strict,
        Named formClientId,
        bool withObject,
        Named claimClientId,
        Named signer,
        HttpStatusCode expectedStatus,
        string? expectedError)
    {
        await using var host = strict ? CreateStrictHost() : Factory.WithWebHostBuilder(_ => { });
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var poster = await RegisterBasicSigningClientAsync(client, discovery, requireSignedRequestObject: false);
        var other = await RegisterBasicSigningClientAsync(client, discovery, requireSignedRequestObject: false);
        SigningClient? Of(Named named) => named switch
        {
            Named.Nobody => null,
            Named.Poster => poster,
            Named.Other => other,
            _ => throw new ArgumentOutOfRangeException(nameof(named)),
        };

        var challenge = GeneratePkcePair().Challenge;
        var form = withObject
            ? new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.Request] =
                    await SignNamingAsync(discovery, Of(signer)!, Of(claimClientId)?.ClientId, challenge),
            }
            : CodeFlowParameters(poster.ClientId, challenge);
        if (Of(formClientId) is { } named)
            form[AuthorizationRequest.Parameters.ClientId] = named.ClientId;
        else
            form.Remove(AuthorizationRequest.Parameters.ClientId);

        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.PushedAuthorizationRequestEndpoint!)
        {
            Content = new FormUrlEncodedContent(form),
        };
        request.Headers.Authorization = BasicAuthenticationOf(poster);
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(expectedStatus, response.StatusCode);
        if (expectedError is not null)
            Assert.Equal(expectedError, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// RFC 9101 section 5: "client_id REQUIRED. OAuth 2.0 [RFC6749] "client_id". The value MUST match the "request" or
    /// "request_uri" Request Object's (Section 2.1) "client_id"." At the authorization endpoint a request object by
    /// value or by reference without a client_id beside it is an invalid_request.
    /// </summary>
    [Theory]
    // Section 5: "request" without client_id beside it
    [InlineData(true)]
    // Section 5: "request_uri" without client_id beside it
    [InlineData(false)]
    public async Task ARequestObjectWithoutAnOuterClientId_IsAnInvalidRequestAtTheAuthorizationEndpoint(bool byValue)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var poster = await RegisterBasicSigningClientAsync(client, discovery, requireSignedRequestObject: false);

        var parameters = byValue
            ? new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.Request] =
                    await SignNamingAsync(discovery, poster, poster.ClientId, GeneratePkcePair().Challenge),
            }
            : new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.RequestUri] = "https://client.example.com/request.jwt",
            };

        await AssertInvalidRequestAsync(client, QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters));
    }

    /// <summary>
    /// The positive control of the rows above: the same request object with the client_id it names beside it is
    /// served, ending in an authorization code.
    /// </summary>
    [Fact]
    public async Task ARequestObjectWithItsClientIdBesideIt_IsServedAtTheAuthorizationEndpoint()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var poster = await RegisterBasicSigningClientAsync(client, discovery, requireSignedRequestObject: false);

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = poster.ClientId,
            [AuthorizationRequest.Parameters.Request] =
                await SignNamingAsync(discovery, poster, poster.ClientId, GeneratePkcePair().Challenge),
        });

        Assert.False(string.IsNullOrEmpty(code));
    }

    /// <summary>
    /// A request object signed with <paramref name="signer"/>'s key and issued by it, carrying a code flow request
    /// whose client_id claim is <paramref name="claimClientId"/>, or none where that is null.
    /// </summary>
    private static async Task<string> SignNamingAsync(
        DiscoveryDocument discovery,
        SigningClient signer,
        string? claimClientId,
        string challenge)
    {
        var now = TimeProvider.System.GetUtcNow();
        var requestJwt = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256, KeyId = signer.Key.KeyId },
            Payload =
            {
                Issuer = signer.ClientId,
                Audiences = [discovery.Issuer.OriginalString],
                IssuedAt = now,
                NotBefore = now,
                ExpiresAt = now.AddMinutes(5),
            },
        };
        foreach (var (name, value) in CodeFlowParameters(signer.ClientId, challenge))
            requestJwt.Payload.Json[name] = value;

        if (claimClientId is null)
            requestJwt.Payload.Json.Remove(AuthorizationRequest.Parameters.ClientId);
        else
            requestJwt.Payload.Json[AuthorizationRequest.Parameters.ClientId] = claimClientId;

        return await JwtServices.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(requestJwt, signer.Key);
    }
}
