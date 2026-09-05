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
using Abblix.Oidc.Server.Model;
using Xunit;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// JWT Secured Authorization Response Mode (JARM). The client requests <c>response_mode=query.jwt</c>; the
/// authorization server returns the authorization response parameters packed into a single signed
/// <c>response</c> JWT carrying the JARM-mandated <c>iss</c>/<c>aud</c>/<c>exp</c> claims (JARM §2.1). The
/// end-to-end invariant: the authorization code lives inside the response JWT, not as a bare query parameter,
/// and that code is still redeemable at the token endpoint.
/// </summary>
public class JwtSecuredAuthorizationResponseTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task QueryJwt_packs_authorization_response_into_signed_jwt()
    {
        var httpClient = CreateClient();
        var discovery = await FetchDiscoveryAsync(httpClient);
        var (verifier, challenge) = GeneratePkcePair();

        // Register a code-flow client. No JARM-specific registration is required: the response is signed with
        // the server's default algorithm (RS256, JARM §3); the client opts in purely by the response mode.
        var dcrBody = new JsonObject
        {
            [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            ["grant_types"] = new JsonArray { GrantTypes.AuthorizationCode },
            ["response_types"] = new JsonArray { ResponseTypes.Code },
            ["token_endpoint_auth_method"] = "client_secret_post",
        };
        var registered = await RegisterClientAsync(httpClient, discovery, dcrBody);
        var clientId = registered[AuthorizationRequest.Parameters.ClientId]!.GetValue<string>();
        var clientSecret = registered[ClientRequest.Parameters.ClientSecret]!.GetValue<string>();

        var state = Guid.NewGuid().ToString("N");

        // Drive /authorize requesting the JARM query.jwt response mode.
        var responseJwt = await AuthorizeAndExtractResponseJwtAsync(httpClient, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = state,
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
            [AuthorizationRequest.Parameters.ResponseMode] = ResponseModes.QueryJwt,
        });

        // The callback carries a 3-segment JWS, not bare query parameters.
        Assert.Equal(3, responseJwt.Split('.').Length);

        var payload = DecodeJwtPayload(responseJwt);

        // JARM §2.1 mandated claims. Compare the issuer ignoring a trailing slash (Uri.AbsoluteUri keeps one,
        // the issuer identifier does not).
        Assert.Equal(
            discovery.Issuer.AbsoluteUri.TrimEnd('/'),
            payload["iss"]!.GetValue<string>().TrimEnd('/'));
        Assert.Equal(clientId, payload["aud"]!.GetValue<string>());
        Assert.NotNull(payload["exp"]);

        // The authorization response parameters are inside the JWT, not on the wire.
        Assert.Equal(state, payload[AuthorizationRequest.Parameters.State]!.GetValue<string>());
        var code = payload[TokenRequest.Parameters.Code]!.GetValue<string>();
        Assert.False(string.IsNullOrEmpty(code));

        // The code extracted from the response JWT is a real, redeemable authorization code.
        var tokenResponse = await ExchangeCodeForTokensAsync(httpClient, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = clientSecret,
        });

        Assert.NotNull(tokenResponse[UserInfoRequest.Parameters.AccessToken]);
    }
}
