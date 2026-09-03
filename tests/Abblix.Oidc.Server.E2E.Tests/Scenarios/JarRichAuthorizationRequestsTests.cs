// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Common.Constants;
using Xunit;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 9101 JWT-Secured Authorization Request (JAR) + RFC 9396 Rich Authorization Requests (RAR)
/// interaction. The client signs a JWT containing all the authorize parameters -- including
/// <c>authorization_details</c> -- and presents it as the <c>request</c> parameter at the
/// authorization endpoint. The AS unpacks the JWT, validates its signature against the client's
/// registered <c>jwks</c>, and runs the standard authorize pipeline (including the RAR per-type
/// validator) on the unpacked claims. The end-to-end invariant: AD propagates from inside the
/// signed request object all the way to the access-token claim byte-exact.
/// </summary>
public class JarRichAuthorizationRequestsTests(TestFactory factory) : TestBase(factory)
{
    private const string PaymentInitiationWireJson =
        """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";

    private static readonly IServiceProvider JwtServices = BuildJwtServices();

    private static IServiceProvider BuildJwtServices()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task SignedRequestObject_carries_authorization_details_into_access_token()
    {
        var httpClient = CreateClient();
        var discovery = await FetchDiscoveryAsync(httpClient);
        var (verifier, challenge) = GeneratePkcePair();

        // 1. Generate an RSA signing keypair for the test client. The PRIVATE key stays in the
        // test for request-object signing; the PUBLIC key goes into the client's jwks via DCR.
        var clientKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

        // 2. Register a client via DCR with the public key inline as jwks. The client uses
        // client_secret_post for token-endpoint authentication (DCR returns a generated secret),
        // the registered jwks is used only by IClientJwtValidator to verify the signed request
        // object at /authorize.
        var dcrBody = new JsonObject
        {
            [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            ["grant_types"] = new JsonArray { GrantTypes.AuthorizationCode },
            ["response_types"] = new JsonArray { "code" },
            ["token_endpoint_auth_method"] = "client_secret_post",
            ["jwks"] = JsonSerializer.SerializeToNode(PublicJwksFor(clientKey)),
            ["authorization_details_types"] = new JsonArray { TestConstants.PaymentInitiationType },
        };
        var registered = await RegisterClientAsync(httpClient, discovery, dcrBody);
        var clientId = registered[AuthorizationRequest.Parameters.ClientId]!.GetValue<string>();
        var clientSecret = registered[ClientRequest.Parameters.ClientSecret]!.GetValue<string>();

        // 3. Build the request JWT containing every authorize parameter -- including the wire-shape
        // authorization_details JSON array attached as a custom claim. RFC 9101 section 6: iss = client_id,
        // aud = the AS issuer; iat / exp pin the request lifetime. The aud must be the issuer
        // identifier byte-exact: AbsoluteUri appends a trailing slash to a root URL, which the
        // server's exact-match audience validation rightly rejects.
        var now = TimeProvider.System.GetUtcNow();
        var requestJwt = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256, KeyId = clientKey.KeyId },
            Payload =
            {
                Issuer = clientId,
                Audiences = [discovery.Issuer.OriginalString],
                IssuedAt = now,
                ExpiresAt = now.AddMinutes(5),
            },
        };
        requestJwt.Payload.Json[AuthorizationRequest.Parameters.ResponseType] = "code";
        requestJwt.Payload.Json[AuthorizationRequest.Parameters.ClientId] = clientId;
        requestJwt.Payload.Json[AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri;
        requestJwt.Payload.Json[AuthorizationRequest.Parameters.Scope] = Scopes.OpenId;
        requestJwt.Payload.Json[AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N");
        requestJwt.Payload.Json[AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N");
        requestJwt.Payload.Json[AuthorizationRequest.Parameters.CodeChallenge] = challenge;
        requestJwt.Payload.Json[AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256;
        requestJwt.Payload.Json[AuthorizationRequest.Parameters.AuthorizationDetails] = JsonNode.Parse(PaymentInitiationWireJson);

        var creator = JwtServices.GetRequiredService<IJsonWebTokenCreator>();
        var signedRequest = await creator.IssueAsync(requestJwt, clientKey);

        // 4. Submit /authorize with request=<signed JWT> + client_id. RFC 9101 section 5 allows every
        // wire parameter inside the JWT plus client_id outside (so the AS can resolve jwks before
        // verifying the signature).
        var code = await AuthorizeAndExtractCodeAsync(httpClient, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            ["request"] = signedRequest,
        });

        // 5. /token exchange.
        var tokenResponse = await ExchangeCodeForTokensAsync(httpClient, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = clientSecret,
        });

        // 6. The access token must carry the same authorization_details the request JWT carried,
        // byte-exact. This is the JAR + RAR invariant: signed request object preserves nested
        // claims through every layer (JWT validation -> request-object fetcher -> standard
        // authorize pipeline -> RAR per-type validator -> consent -> token emission).
        var payload = DecodeJwtPayload(tokenResponse[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        var claim = (payload[AuthorizationRequest.Parameters.AuthorizationDetails] as JsonArray)!;
        Assert.NotNull(claim);
        Assert.Equal(PaymentInitiationWireJson, claim.ToJsonString());
    }

    /// <summary>
    /// Strips the private RSA components from a signing key, leaving only the modulus (n) and
    /// public exponent (e) plus identifying metadata. RFC 7517 section 6: a public JWK MUST NOT include
    /// private fields; sending the full private key over the wire to a registration endpoint is a
    /// catastrophic leak even in a test.
    /// </summary>
    private static JsonWebKeySet PublicJwksFor(RsaJsonWebKey privateKey)
    {
        var publicJwk = new RsaJsonWebKey
        {
            Algorithm = privateKey.Algorithm,
            Usage = privateKey.Usage,
            KeyId = privateKey.KeyId,
            Exponent = privateKey.Exponent,
            Modulus = privateKey.Modulus,
        };
        return new JsonWebKeySet([publicJwk]);
    }
}
