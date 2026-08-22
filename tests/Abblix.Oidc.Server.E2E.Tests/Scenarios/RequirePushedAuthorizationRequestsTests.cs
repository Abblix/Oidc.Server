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
using Abblix.Oidc.Server.Model;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 9126 §6 per-client <c>require_pushed_authorization_requests</c> end-to-end: a flagged
/// client can only start an authorization flow via PAR. The critical property locked here is that
/// the PAR endpoint itself accepts the flagged client - the requirement must not deadlock the only
/// entry point the client is allowed to use - while a plain /authorize request is rejected.
/// </summary>
public class RequirePushedAuthorizationRequestsTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task FlaggedClient_CompletesParFlow_WhilePlainAuthorizeIsRejected()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        // 1. Register a client committed to PAR; the flag must round-trip in the DCR response.
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [ClientRegistrationRequest.Parameters.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            [ClientRegistrationRequest.Parameters.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
            [ClientRegistrationRequest.Parameters.ResponseTypes] = new JsonArray { ResponseTypes.Code },
            [ClientRegistrationRequest.Parameters.TokenEndpointAuthMethod] =
                ClientAuthenticationMethods.ClientSecretPost,
            [ClientRegistrationRequest.Parameters.RequirePushedAuthorizationRequests] = true,
        });
        var clientId = registered[AuthorizationRequest.Parameters.ClientId]!.GetValue<string>();
        var clientSecret = registered[ClientRequest.Parameters.ClientSecret]!.GetValue<string>();
        Assert.True(
            registered[ClientRegistrationRequest.Parameters.RequirePushedAuthorizationRequests]!.GetValue<bool>());

        // 2. The PAR endpoint accepts the flagged client and issues a request_uri - the per-client
        // requirement is enforced only at the authorization endpoint.
        var (_, challenge) = GeneratePkcePair();
        var parResponse = await PushAuthorizationRequestAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = clientSecret,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        });
        var requestUri = parResponse[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>();

        // 3. /authorize with the PAR-issued request_uri completes and yields a code.
        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.RequestUri] = requestUri,
        });
        Assert.NotEmpty(code);

        // 4. A plain /authorize request from the same client is rejected: no code may be issued
        // outside PAR. The rejection happens at the fetch stage, before redirect validation, so
        // it surfaces as a direct error response rather than an error redirect.
        var (_, plainChallenge) = GeneratePkcePair();
        var plainAuthorizeUri = QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.CodeChallenge] = plainChallenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        });
        var plainResponse = await client.GetAsync(plainAuthorizeUri, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, plainResponse.StatusCode);
        var responseText = await plainResponse.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var body = JsonNode.Parse(responseText)!.AsObject();
        Assert.Equal(ErrorCodes.InvalidRequestObject, body[ResponseParameters.Error]!.GetValue<string>());
    }
}
