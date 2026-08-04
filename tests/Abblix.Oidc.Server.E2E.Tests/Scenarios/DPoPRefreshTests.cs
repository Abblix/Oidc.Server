// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 9449 §5 refresh-token rebinding for DPoP, end-to-end against the test OIDC
/// provider. Covers the same-key MUST for public clients, the confidential-client
/// carve-out (refresh tokens already sender-constrained by client authentication may
/// rotate keys), and both PAR-anchored and non-PAR binding paths. Token-endpoint
/// binding (§6) lives in <see cref="DPoPTests"/> and resource access (§9) in
/// <see cref="DPoPUserInfoTests"/>; the three share <see cref="DPoPTestBase"/>.
/// </summary>
public class DPoPRefreshTests(TestFactory factory) : DPoPTestBase(factory)
{
    [Fact]
    public async Task Refresh_with_same_dpop_key_yields_new_token_bound_to_same_jkt()
    {
        // RFC 9449 §5: when refreshing a DPoP-bound access token, the new token MUST be
        // bound to the same key as the previous one. Abblix enforces this via the §10
        // carry-over mechanism - the original grant's ProofKeyThumbprint is committed on
        // the refresh token and DPoPTokenEndpointValidator rejects any proof key drift.
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var refreshToken = await ObtainRefreshTokenBoundToAsync(
            client, discovery, TestConstants.DPoPOpportunisticClientId, proofKey);

        // Fresh proof (new jti, current iat) signed by the SAME keypair.
        var refreshProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var refreshHttp = await SendRefreshAsync(
            client, discovery, refreshToken, TestConstants.DPoPOpportunisticClientId, refreshProof);

        var raw = await refreshHttp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(refreshHttp.IsSuccessStatusCode,
            $"/token refresh failed: {(int)refreshHttp.StatusCode} {raw}");
        var refreshBody = JsonNode.Parse(raw)!.AsObject();
        AssertDPoPBound(refreshBody, expectedThumbprint: proofKey.Thumbprint);
    }

    [Fact]
    public async Task Confidential_client_can_rebind_to_new_dpop_key_on_refresh()
    {
        // RFC 9449 §5 explicit carve-out: «Refresh tokens issued to confidential
        // clients (those having established authentication credentials with the
        // authorization server) are not bound to the DPoP proof public key because
        // they are already sender-constrained with a different existing mechanism»
        // (client authentication). The AS therefore accepts a fresh DPoP key on
        // refresh and binds the new access token to it - a confidential client may
        // rotate keys without re-running the auth-code dance. The strict
        // same-key-MUST rule of §5 applies only to PUBLIC clients; a no-secret
        // seeded client is out of scope for this slice.
        using var originalKey = new DPoPProofGenerator();
        using var rotatedKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var refreshToken = await ObtainRefreshTokenBoundToAsync(
            client, discovery, TestConstants.DPoPOpportunisticClientId, originalKey);

        // Refresh with a freshly rotated key - must succeed and the new access token
        // must be bound to the rotated key (not the original one).
        var rotatedProof = rotatedKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var refreshHttp = await SendRefreshAsync(
            client, discovery, refreshToken, TestConstants.DPoPOpportunisticClientId, rotatedProof);

        var raw = await refreshHttp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(refreshHttp.IsSuccessStatusCode,
            $"/token refresh failed: {(int)refreshHttp.StatusCode} {raw}");
        var refreshBody = JsonNode.Parse(raw)!.AsObject();
        AssertDPoPBound(refreshBody, expectedThumbprint: rotatedKey.Thumbprint);
    }

    [Fact]
    public async Task Public_client_refresh_with_same_dpop_key_yields_new_token_bound_to_same_jkt()
    {
        // RFC 9449 §5: public clients (token_endpoint_auth_method = none) lack a shared
        // secret, so DPoP is the sole sender-constraint. Same-key MUST therefore be
        // enforced on refresh. Abblix carries the thumbprint forward via the §10
        // PAR-time commitment path; a proof on the PAR request commits dpop_jkt into
        // the stored authorization request, the auth code restores it, and refresh
        // tokens for public clients keep it (vs. confidential clients which strip).
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var parProof = proofKey.BuildProof(HttpMethods.Post, discovery.PushedAuthorizationRequestEndpoint!);
        var refreshToken = await ObtainRefreshTokenBoundToAsync(
            client, discovery, TestConstants.DPoPPublicClientId, proofKey,
            parProof: parProof, clientSecret: null);

        var refreshProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var refreshHttp = await SendRefreshAsync(
            client, discovery, refreshToken, TestConstants.DPoPPublicClientId, refreshProof, clientSecret: null);

        var raw = await refreshHttp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(refreshHttp.IsSuccessStatusCode,
            $"/token refresh failed: {(int)refreshHttp.StatusCode} {raw}");
        var refreshBody = JsonNode.Parse(raw)!.AsObject();
        AssertDPoPBound(refreshBody, expectedThumbprint: proofKey.Thumbprint);
    }

    [Fact]
    public async Task Public_client_non_par_refresh_with_same_dpop_key_yields_new_token_bound_to_same_jkt()
    {
        // RFC 9449 §5 applies regardless of how the initial token was obtained - a
        // proof at /token alone (no PAR commitment) is enough to bind the access
        // token, and the binding MUST flow through to the refresh token. Pins the
        // TokenRequestProcessor fix: public-flow refreshContext sources its thumbprint
        // from authContext (live proof) rather than from the un-evaluated grant
        // context (which is null without PAR).
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var refreshToken = await ObtainRefreshTokenBoundToAsync(
            client, discovery, TestConstants.DPoPPublicClientId, proofKey, clientSecret: null);

        var refreshProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var refreshHttp = await SendRefreshAsync(
            client, discovery, refreshToken, TestConstants.DPoPPublicClientId, refreshProof, clientSecret: null);

        var raw = await refreshHttp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(refreshHttp.IsSuccessStatusCode,
            $"/token refresh failed: {(int)refreshHttp.StatusCode} {raw}");
        AssertDPoPBound(JsonNode.Parse(raw)!.AsObject(), expectedThumbprint: proofKey.Thumbprint);
    }

    [Fact]
    public async Task Public_client_non_par_refresh_with_different_dpop_key_is_rejected_per_rfc9449_section5()
    {
        // Regression pin for the TokenRequestProcessor fix. Before the fix the public
        // refresh path sourced refreshContext from request.AuthorizedGrant.Context,
        // which carried no ProofKeyThumbprint for non-PAR flows; the validator's
        // committed-vs-presented compare then short-circuited (committed = null) and
        // a rotated key was silently accepted - a §5 MUST violation. Post-fix the
        // refresh JWT carries cnf.jkt from authContext (live proof's thumbprint), so
        // the next refresh's mismatched proof is caught.
        using var originalKey = new DPoPProofGenerator();
        using var attackerKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var refreshToken = await ObtainRefreshTokenBoundToAsync(
            client, discovery, TestConstants.DPoPPublicClientId, originalKey, clientSecret: null);

        var attackerProof = attackerKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var refreshHttp = await SendRefreshAsync(
            client, discovery, refreshToken, TestConstants.DPoPPublicClientId, attackerProof, clientSecret: null);

        Assert.Equal(HttpStatusCode.BadRequest, refreshHttp.StatusCode);
        var body = JsonNode.Parse(await refreshHttp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(ErrorCodes.InvalidDPoPProof, body[ResponseParameters.Error]!.GetValue<string>());
    }

    [Fact]
    public async Task Public_client_refresh_with_different_dpop_key_is_rejected_per_rfc9449_section5()
    {
        // RFC 9449 §5 MUST for public clients: «such a client MUST present a DPoP proof
        // for the same key that was used to obtain the refresh token each time that
        // refresh token is used». A rotated key on refresh is the canonical theft
        // scenario the constraint exists to close - without a shared secret, the proof
        // key is the only thing tying the holder to the original grant. Commitment is
        // anchored at PAR (Abblix §10 carry-over path); a proof on PAR makes the AS
        // pin dpop_jkt onto the stored authorization request, and the public-client
        // refresh path preserves the binding through to subsequent token requests.
        using var originalKey = new DPoPProofGenerator();
        using var attackerKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var parProof = originalKey.BuildProof(HttpMethods.Post, discovery.PushedAuthorizationRequestEndpoint!);
        var refreshToken = await ObtainRefreshTokenBoundToAsync(
            client, discovery, TestConstants.DPoPPublicClientId, originalKey,
            parProof: parProof, clientSecret: null);

        var attackerProof = attackerKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var refreshHttp = await SendRefreshAsync(
            client, discovery, refreshToken, TestConstants.DPoPPublicClientId, attackerProof, clientSecret: null);

        Assert.Equal(HttpStatusCode.BadRequest, refreshHttp.StatusCode);
        var body = JsonNode.Parse(await refreshHttp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(ErrorCodes.InvalidDPoPProof, body[ResponseParameters.Error]!.GetValue<string>());
    }

    /// <summary>
    /// Drives an initial PAR -> /authorize -> /token round with <c>offline_access</c>
    /// in scope, asserts the resulting access token is DPoP-bound to <paramref name="proofKey"/>,
    /// and returns the issued refresh token. Common bootstrap for every refresh-rebinding
    /// scenario - confidential vs public, PAR-anchored vs non-PAR.
    /// </summary>
    private static async Task<string> ObtainRefreshTokenBoundToAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        DPoPProofGenerator proofKey,
        string? parProof = null,
        string? clientSecret = TestConstants.ConfidentialClientSecret)
    {
        var initial = await DriveParAuthorizeTokenAsync(
            client, discovery,
            clientId: clientId,
            parProof: parProof,
            tokenProof: proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint),
            scope: $"{Scopes.OpenId} {Scopes.OfflineAccess}",
            clientSecret: clientSecret);

        AssertDPoPBound(initial, expectedThumbprint: proofKey.Thumbprint);
        return initial[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();
    }

    /// <summary>
    /// Sends a refresh_token grant request with a DPoP proof. The refresh token is
    /// taken from the previous token response; the proof must be signed by the same
    /// keypair the original access token was bound to (RFC 9449 §5 + §10 carry-over).
    /// </summary>
    private static async Task<HttpResponseMessage> SendRefreshAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string refreshToken,
        string clientId,
        string proofJwt,
        string? clientSecret = TestConstants.ConfidentialClientSecret)
    {
        var form = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.RefreshToken,
            [TokenRequest.Parameters.RefreshToken] = refreshToken,
            [ClientRequest.Parameters.ClientId] = clientId,
        };
        if (clientSecret is not null)
            form[ClientRequest.Parameters.ClientSecret] = clientSecret;
        return await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, form, proofJwt);
    }
}
