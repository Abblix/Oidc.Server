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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end coverage for ID tokens encrypted with the ECDH-ES key management family (OIDC Core §10.2):
/// a client registers an EC encryption key via DCR together with <c>id_token_encrypted_response_alg</c>,
/// completes the authorization code flow through the real endpoints and receives its ID token as a JWE
/// it can decrypt with the EC private key. The <c>ECDH-ES+A256KW</c> case also drives the RFC 3394
/// AES Key Wrap on the issuing side. PBES2 has no server-level scenario by construction - client
/// metadata carries no password channel - so its coverage is the full-pipeline creator/validator suite,
/// which exercises exactly the code path the server invokes.
/// </summary>
public class EncryptedIdTokenTests(TestFactory factory) : TestBase(factory)
{
    [Theory]
    [InlineData(
        EncryptionAlgorithms.KeyManagement.EcdhEs,
        // 512-bit CEK: the Concat KDF runs two SHA-256 rounds on the issuing server
        EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)]
    [InlineData(
        EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW,
        EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256)]
    public async Task IdToken_EncryptedToClientEcKey_ClientDecryptsAndValidates(
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm)
    {
        var httpClient = CreateClient();
        var discovery = await FetchDiscoveryAsync(httpClient);

        // The client's EC key pair: the private part stays on the "client" (this test),
        // the public part is registered in the DCR jwks with use=enc.
        var clientEncryptionKey = JsonWebKeyFactory.CreateEllipticCurve(
            EllipticCurveTypes.P256, SigningAlgorithms.ES256) with
        {
            Usage = PublicKeyUsages.Encryption,
            // The registered id_token_encrypted_response_alg governs the key management algorithm;
            // the key itself does not pin one.
            Algorithm = null,
        };
        var clientPublicJwk = clientEncryptionKey.Sanitize(includePrivateKeys: false);

        var (verifier, challenge) = GeneratePkcePair();
        var nonce = Guid.NewGuid().ToString("N");

        var registered = await RegisterClientAsync(httpClient, discovery, new JsonObject
        {
            [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            ["grant_types"] = new JsonArray { GrantTypes.AuthorizationCode },
            ["response_types"] = new JsonArray { ResponseTypes.Code },
            ["token_endpoint_auth_method"] = "client_secret_post",
            [ClientRegistrationRequest.Parameters.IdTokenEncryptedResponseAlg] = keyManagementAlgorithm,
            [ClientRegistrationRequest.Parameters.IdTokenEncryptedResponseEnc] = contentEncryptionAlgorithm,
            [ClientRegistrationRequest.Parameters.Jwks] =
                JsonSerializer.SerializeToNode(new JsonWebKeySet([clientPublicJwk])),
        });
        var clientId = registered[AuthorizationRequest.Parameters.ClientId]!.GetValue<string>();
        var clientSecret = registered[ClientRequest.Parameters.ClientSecret]!.GetValue<string>();

        var code = await AuthorizeAndExtractCodeAsync(httpClient, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = nonce,
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        });

        var tokenResponse = await ExchangeCodeForTokensAsync(httpClient, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = clientSecret,
        });

        var idToken = tokenResponse[ResponseParameters.IdToken]!.GetValue<string>();

        // The ID token arrives as a JWE (five parts) declaring the registered algorithms; in Direct
        // Key Agreement mode the encrypted key is empty and the agreement travels as 'epk'.
        var parts = idToken.Split('.');
        Assert.Equal(5, parts.Length);

        var header = JsonNode.Parse(Base64UrlDecodeToString(parts[0]))!.AsObject();
        Assert.Equal(keyManagementAlgorithm, header[JwtClaimTypes.Algorithm]!.GetValue<string>());
        Assert.Equal(contentEncryptionAlgorithm, header[JwtClaimTypes.EncryptionAlgorithm]!.GetValue<string>());
        Assert.True(header.ContainsKey(JwtClaimTypes.EphemeralPublicKey));
        if (keyManagementAlgorithm == EncryptionAlgorithms.KeyManagement.EcdhEs)
            Assert.Empty(parts[1]);

        // The client decrypts with its EC private key and validates the inner JWS against the
        // server's published signing keys - the complete consume side of the flow.
        var serverJwks = JsonSerializer.Deserialize<JsonWebKeySet>(
            await httpClient.GetStringAsync(discovery.JwksUri, TestContext.Current.CancellationToken));
        Assert.NotNull(serverJwks);

        var validationResult = await CreateValidator().ValidateAsync(idToken, new ValidationParameters
        {
            ValidateIssuer = iss => Task.FromResult(
                iss.TrimEnd('/') == discovery.Issuer.AbsoluteUri.TrimEnd('/')),
            ValidateAudience = aud => Task.FromResult(aud.Contains(clientId)),
            ResolveIssuerSigningKeys = _ => serverJwks.Keys.ToAsyncEnumerable(),
            ResolveTokenDecryptionKeys = _ => new JsonWebKey[] { clientEncryptionKey }.ToAsyncEnumerable(),
        });

        Assert.True(validationResult.TryGetSuccess(out var token),
            validationResult.TryGetFailure(out var error)
                ? $"ID token validation failed for {keyManagementAlgorithm}: {error.Error} - {error.ErrorDescription}"
                : "ID token validation failed");
        Assert.Equal(nonce, token.Payload.Nonce);
        Assert.Contains(clientId, token.Payload.Audiences);
    }

    private static IJsonWebTokenValidator CreateValidator()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider().GetRequiredService<IJsonWebTokenValidator>();
    }

    private static string Base64UrlDecodeToString(string value)
        => System.Text.Encoding.UTF8.GetString(System.Buffers.Text.Base64Url.DecodeFromChars(value));
}
