// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 8705 section 3.4: tls_client_certificate_bound_access_tokens conveys "the client's intention to use mutual-TLS
/// client certificate-bound access tokens. If omitted, the default value is false." A client authenticating with
/// mutual TLS that did not register it and sender-constrains its tokens with DPoP gets a token bound to its proof key
/// alone, so it calls a protected resource with the proof and no certificate; one that registered it gets a token
/// bound to its certificate as well, which the resource refuses without that certificate (RFC 8705 section 3).
/// </summary>
public class CertificateBoundAccessTokenTests(TestFactory factory) : DPoPTestBase(factory)
{
    private const string SubjectDn = "CN=e2e-mutual-tls-client";
    private const string UnregisteredClientId = "e2e-mutual-tls-dpop";
    private const string RegisteredClientId = "e2e-mutual-tls-certificate-bound";

    [Fact]
    public async Task Mutual_tls_client_not_registered_for_certificate_binding_gets_a_token_bound_to_its_proof_key_only()
    {
        using var certificate = CreateCertificate();
        using var proofKey = new DPoPProofGenerator();
        await using var host = HostWithMutualTlsClients();
        using var withCertificate = ClientPresenting(host, certificate);
        using var withoutCertificate = ClientPresenting(host, null);
        var discovery = await FetchDiscoveryAsync(withoutCertificate);

        var accessToken = await ObtainAccessTokenAsync(withCertificate, discovery, UnregisteredClientId, proofKey);

        // The resource call with the proof and no certificate comes first: it is what a client of this kind does, and
        // a token bound to the certificate as well fails it with 401 before the claims below are read
        using var response = await SendUserInfoAsync(withoutCertificate, discovery, accessToken, proofKey);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{(int)response.StatusCode}: {body}");

        var confirmation = ConfirmationOf(accessToken);
        Assert.Equal(proofKey.Thumbprint, confirmation[IanaClaimTypes.ConfirmationMethods.JwkThumbprint]?.GetValue<string>());
        Assert.Null(confirmation[IanaClaimTypes.ConfirmationMethods.CertificateSha256Thumbprint]);
    }

    [Fact]
    public async Task Mutual_tls_client_registered_for_certificate_binding_gets_a_token_bound_to_its_certificate_too()
    {
        using var certificate = CreateCertificate();
        using var proofKey = new DPoPProofGenerator();
        await using var host = HostWithMutualTlsClients();
        using var withCertificate = ClientPresenting(host, certificate);
        using var withoutCertificate = ClientPresenting(host, null);
        var discovery = await FetchDiscoveryAsync(withoutCertificate);

        var accessToken = await ObtainAccessTokenAsync(withCertificate, discovery, RegisteredClientId, proofKey);

        var confirmation = ConfirmationOf(accessToken);
        Assert.Equal(proofKey.Thumbprint, confirmation[IanaClaimTypes.ConfirmationMethods.JwkThumbprint]?.GetValue<string>());
        Assert.Equal(
            Base64Url.EncodeToString(SHA256.HashData(certificate.RawData)),
            confirmation[IanaClaimTypes.ConfirmationMethods.CertificateSha256Thumbprint]?.GetValue<string>());

        using var refused = await SendUserInfoAsync(withoutCertificate, discovery, accessToken, proofKey);
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);

        using var served = await SendUserInfoAsync(withCertificate, discovery, accessToken, proofKey);
        var body = await served.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(served.StatusCode == HttpStatusCode.OK, $"{(int)served.StatusCode}: {body}");
    }

    /// <summary>
    /// The shared host with two clients authenticating with tls_client_auth by the same subject, one of them
    /// registered for certificate-bound access tokens.
    /// </summary>
    private WebApplicationFactory<Program> HostWithMutualTlsClients()
        => Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.PostConfigure<TestTenantSettings>(tenant => tenant.Clients =
            [
                ..tenant.Clients,
                MutualTlsClient(UnregisteredClientId, certificateBoundAccessTokens: false),
                MutualTlsClient(RegisteredClientId, certificateBoundAccessTokens: true),
            ])));

    private static ClientInfo MutualTlsClient(string clientId, bool certificateBoundAccessTokens) => new(clientId)
    {
        TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
        TlsClientAuth = new TlsClientAuthOptions { SubjectDn = SubjectDn },
        TlsClientCertificateBoundAccessTokens = certificateBoundAccessTokens,
        AllowedGrantTypes = [GrantTypes.AuthorizationCode],
        PkceRequired = true,
        RedirectUris = [new Uri(TestConstants.RedirectUri, UriKind.Absolute)],
    };

    /// <summary>
    /// A client of <paramref name="host"/> whose every connection carries <paramref name="certificate"/>, or none.
    /// </summary>
    private static HttpClient ClientPresenting(WebApplicationFactory<Program> host, X509Certificate2? certificate)
        => new(host.Server.CreateHandler(context => context.Connection.ClientCertificate = certificate))
        {
            BaseAddress = TestServerAddress.BaseAddress,
        };

    /// <summary>
    /// Drives PAR, the authorization endpoint and the token endpoint for <paramref name="clientId"/>, authenticated by
    /// the certificate <paramref name="client"/> carries, with a DPoP proof at the token endpoint.
    /// </summary>
    private static async Task<string> ObtainAccessTokenAsync(
        HttpClient client, DiscoveryDocument discovery, string clientId, DPoPProofGenerator proofKey)
    {
        var tokenResponse = await DriveParAuthorizeTokenAsync(
            client,
            discovery,
            clientId,
            parProof: null,
            tokenProof: proofKey.BuildProof(HttpMethods.Post, discovery.TokenEndpoint),
            clientSecret: null);

        return tokenResponse[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
    }

    private static JsonObject ConfirmationOf(string accessToken)
    {
        var confirmation = DecodeJwtPayload(accessToken)[IanaClaimTypes.Cnf];
        return Assert.IsType<JsonObject>(confirmation);
    }

    private static async Task<HttpResponseMessage> SendUserInfoAsync(
        HttpClient client, DiscoveryDocument discovery, string accessToken, DPoPProofGenerator proofKey)
    {
        Assert.NotNull(discovery.UserInfoEndpoint);
        using var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.DPoP, accessToken);
        request.WithDPoPHeader(proofKey.BuildProof(HttpMethods.Get, discovery.UserInfoEndpoint, accessToken: accessToken));
        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var key = RSA.Create(2048);
        return new CertificateRequest(SubjectDn, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(TimeProvider.System.GetUtcNow().AddDays(-1), TimeProvider.System.GetUtcNow().AddDays(1));
    }
}
