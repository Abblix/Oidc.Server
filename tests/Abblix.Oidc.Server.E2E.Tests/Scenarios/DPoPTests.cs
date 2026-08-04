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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 9449 §6 token-endpoint binding (and §4.2 discovery advertisement) for DPoP,
/// end-to-end against the test OIDC provider. Each test mints a proof with a
/// per-instance ECDSA P-256 keypair, threads it through the real HTTP flow
/// (PAR -> /authorize -> /token), and asserts on the wire-level outcome: the issued
/// access token's <c>cnf.jkt</c> claim, the wire <c>token_type</c>, or the error code
/// returned by the AS. Refresh-token rebinding (§5) lives in
/// <see cref="DPoPRefreshTests"/> and resource access (§9) in
/// <see cref="DPoPUserInfoTests"/>; the three share <see cref="DPoPTestBase"/>.
/// </summary>
/// <remarks>
/// Two seeded clients drive the matrix:
/// <see cref="TestConstants.DPoPRequiredClientId"/> -- <c>RequireDPoP = true</c>
/// (mandatory binding; missing proof -> reject) and
/// <see cref="TestConstants.DPoPOpportunisticClientId"/> -- <c>RequireDPoP = false</c>
/// (proof optional; when present the AS still binds, RFC 9449 §5.2 opportunistic posture).
/// Lower-level helpers from <see cref="TestBase"/> are used directly rather than
/// <c>PerformParFlowAsync</c> because DPoP scenarios need different proofs on different
/// endpoints (one per request) and a few exercise PAR-only or token-only deviations
/// that the wrapper hides.
/// </remarks>
public class DPoPTests(TestFactory factory) : DPoPTestBase(factory)
{
    [Fact]
    public async Task Opportunistic_client_with_proof_at_token_endpoint_gets_dpop_bound_access_token()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokenResponse = await DriveParAuthorizeTokenAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null,
            tokenProof: proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint));

        AssertDPoPBound(tokenResponse, expectedThumbprint: proofKey.Thumbprint);
    }

    [Fact]
    public async Task Opportunistic_client_without_proof_gets_bearer_access_token()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokenResponse = await DriveParAuthorizeTokenAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null,
            tokenProof: null);

        AssertBearer(tokenResponse);
    }

    [Fact]
    public async Task Required_client_with_valid_proof_gets_dpop_bound_access_token()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokenResponse = await DriveParAuthorizeTokenAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPRequiredClientId,
            parProof: null,
            tokenProof: proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint));

        AssertDPoPBound(tokenResponse, expectedThumbprint: proofKey.Thumbprint);
    }

    [Fact]
    public async Task Required_client_without_proof_is_rejected_with_invalid_dpop_proof()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokenError = await DriveParAuthorizeTokenExpectingErrorAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPRequiredClientId,
            parProof: null,
            tokenProof: null);

        Assert.Equal(ErrorCodes.InvalidDPoPProof, tokenError);
    }

    [Fact]
    public async Task Proof_at_par_commits_dpop_jkt_and_matching_proof_at_token_succeeds()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var parProof = proofKey.BuildProof(HttpMethods.Post, discovery.PushedAuthorizationRequestEndpoint!);
        var tokenProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);

        var tokenResponse = await DriveParAuthorizeTokenAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: parProof,
            tokenProof: tokenProof);

        AssertDPoPBound(tokenResponse, expectedThumbprint: proofKey.Thumbprint);
    }

    [Fact]
    public async Task Proof_at_par_followed_by_different_key_at_token_is_rejected()
    {
        // RFC 9449 §10: dpop_jkt committed at PAR pins which key the token endpoint
        // must see; a different key proves the auth code was hijacked by another client.
        using var parKey = new DPoPProofGenerator();
        using var tokenKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var parProof = parKey.BuildProof(HttpMethods.Post, discovery.PushedAuthorizationRequestEndpoint!);
        var tokenProof = tokenKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);

        var tokenError = await DriveParAuthorizeTokenExpectingErrorAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: parProof,
            tokenProof: tokenProof);

        Assert.Equal(ErrorCodes.InvalidDPoPProof, tokenError);
    }

    [Fact]
    public async Task Carry_over_committed_at_par_but_no_proof_at_token_is_rejected()
    {
        // The canonical RFC 9449 §10 attack window: PAR pinned a key, but the redeemer
        // shows up at /token without a proof. Even an opportunistic-binding client MUST
        // reject -- the PAR-time commitment is unconditional.
        using var parKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var parProof = parKey.BuildProof(HttpMethods.Post, discovery.PushedAuthorizationRequestEndpoint!);

        var tokenError = await DriveParAuthorizeTokenExpectingErrorAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: parProof,
            tokenProof: null);

        Assert.Equal(ErrorCodes.InvalidDPoPProof, tokenError);
    }

    [Fact]
    public async Task Same_proof_jwt_presented_twice_is_rejected_on_the_second_attempt()
    {
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        // Mint ONE proof and reuse it across two independent flows. First flow succeeds
        // and the AS caches the proof's jti; second flow with the same proof string trips
        // the replay cache regardless of which other request parameters change.
        var sharedProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);

        var firstResponse = await DriveParAuthorizeTokenAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null,
            tokenProof: sharedProof);
        AssertDPoPBound(firstResponse, expectedThumbprint: proofKey.Thumbprint);

        var secondError = await DriveParAuthorizeTokenExpectingErrorAsync(
            client,
            discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null,
            tokenProof: sharedProof);
        Assert.Equal(ErrorCodes.InvalidDPoPProof, secondError);
    }

    [Fact]
    public async Task Token_endpoint_rejects_proof_whose_htm_does_not_match_the_request_method()
    {
        // RFC 9449 §4.3 step 8: htm MUST match the HTTP method byte-exact. Mint a
        // proof claiming GET, then POST it to /token - the validator should reject
        // and the wire response should carry error=invalid_dpop_proof at HTTP 400.
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var proofForWrongMethod = proofKey.BuildProof(HttpMethods.Get, discovery.TokenEndpoint);

        var error = await DriveParAuthorizeTokenExpectingErrorAsync(
            client, discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null,
            tokenProof: proofForWrongMethod);

        Assert.Equal(ErrorCodes.InvalidDPoPProof, error);
    }

    [Fact]
    public async Task Token_endpoint_rejects_proof_with_corrupted_signature()
    {
        // RFC 9449 §4.3 step 6: signature MUST verify. Mint a valid proof then
        // flip a byte in the signature segment; downstream signature verification
        // fails and the validator returns invalid_dpop_proof - pin the wire shape.
        using var proofKey = new DPoPProofGenerator();
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var validProof = proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint);
        var corrupted = CorruptSignatureSegment(validProof);

        var error = await DriveParAuthorizeTokenExpectingErrorAsync(
            client, discovery,
            clientId: TestConstants.DPoPOpportunisticClientId,
            parProof: null,
            tokenProof: corrupted);

        Assert.Equal(ErrorCodes.InvalidDPoPProof, error);
    }

    [Fact]
    public async Task Discovery_exposes_dpop_signing_alg_values_supported()
    {
        var discovery = await FetchDiscoveryAsync(CreateClient());

        Assert.NotNull(discovery.DPoPSigningAlgValuesSupported);
        // RFC 9449 §4.2 alg whitelist (no HMAC, no none); the AS advertises an asymmetric
        // subset. We pin a few canonical values; full enumeration is a unit-test concern.
        Assert.Contains(SigningAlgorithms.ES256, discovery.DPoPSigningAlgValuesSupported);
        Assert.Contains(SigningAlgorithms.RS256, discovery.DPoPSigningAlgValuesSupported);
        Assert.Contains(SigningAlgorithms.PS256, discovery.DPoPSigningAlgValuesSupported);
        Assert.DoesNotContain(SigningAlgorithms.HS256, discovery.DPoPSigningAlgValuesSupported);
        Assert.DoesNotContain(SigningAlgorithms.None, discovery.DPoPSigningAlgValuesSupported);
    }

    /// <summary>
    /// Tampers with the first character of a JWS's signature segment. The proof
    /// otherwise remains structurally valid (3 dot-separated base64url parts);
    /// only the bytes that signature verification reads change, so the failure
    /// must come from the crypto check rather than from a structural pre-screen.
    /// </summary>
    private static string CorruptSignatureSegment(string proofJws)
    {
        var parts = proofJws.Split('.');
        Assert.Equal(3, parts.Length);
        var sig = parts[2];
        var firstChar = sig[0];
        // Swap with a different valid base64url character to keep the JWS parseable.
        parts[2] = (firstChar == 'A' ? 'B' : 'A') + sig[1..];
        return string.Join('.', parts);
    }
}
