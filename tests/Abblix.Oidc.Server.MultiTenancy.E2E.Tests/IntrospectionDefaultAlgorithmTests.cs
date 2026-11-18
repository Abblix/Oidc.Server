// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// RFC 9701 section 6, introspection_signed_response_alg: "The default, if omitted, is RS256". A client held to no
/// security profile and registering no algorithm is answered with a JWT signed RS256 where a key of the tenant
/// produces it, and with 406 Not Acceptable where none does, rather than with a JWT signed otherwise or a server error.
/// </summary>
public sealed class IntrospectionDefaultAlgorithmTests
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string ClientId = "resource-server";
    private const string ClientSecret = "resource-server-secret";
    private const string Jwt = MediaTypes.TokenIntrospectionJwt;
    private const string Json = System.Net.Mime.MediaTypeNames.Application.Json;

    private static async Task<WebApplication> StartAsync(
        JsonWebKey signingKey,
        string serviceTokenAlgorithm,
        JsonWebKeySet? clientKeys = null,
        string introspectionAlgorithm = SigningAlgorithms.None,
        string? keyManagementAlgorithm = null,
        string? contentEncryptionAlgorithm = null,
        LevelRecordingLoggerProvider? logs = null)
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        if (logs is not null)
            builder.Services.AddSingleton<ILoggerProvider>(logs);
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddIntrospection();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddOidcServices(options =>
        {
            options.EnabledEndpoints = OidcEndpoints.Base | OidcEndpoints.Introspection;
            options.ServiceTokens.AccessToken.Signing.Algorithm = serviceTokenAlgorithm;
            options.ServiceTokens.RefreshToken.Signing.Algorithm = serviceTokenAlgorithm;
            options.ServiceTokens.RegistrationAccessToken.Signing.Algorithm = serviceTokenAlgorithm;
            options.ServiceTokens.InitialAccessToken.Signing.Algorithm = serviceTokenAlgorithm;
        });
        builder.Services.Configure<OidcOptions>(options => options.Tenants.Add(new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri(Host + Acme),
            SigningKeys = [signingKey],
            Clients =
            [
                new ClientInfo(ClientId)
                {
                    ClientSecrets =
                    [
                        new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)) },
                    ],
                    TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                    AllowedGrantTypes = [GrantTypes.ClientCredentials],
                    IdentityTokenSignedResponseAlgorithm = serviceTokenAlgorithm,
                    IntrospectionSignedResponseAlgorithm = introspectionAlgorithm,
                    IntrospectionEncryptedResponseAlgorithm = keyManagementAlgorithm,
                    IntrospectionEncryptedResponseEncryption = contentEncryptionAlgorithm,
                    Jwks = clientKeys,
                },
            ],
        }));

        var app = builder.Build();
        app.UseMultiTenancy();
        app.MapOidcEndpoints();
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task<HttpResponseMessage> IntrospectAsync(
        WebApplication app,
        string accept = MediaTypes.TokenIntrospectionJwt)
    {
        using var http = app.GetTestClient();
        http.BaseAddress = new Uri(Host);

        using var request = new HttpRequestMessage(HttpMethod.Post, Acme + "/connect/introspect")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [IntrospectionRequest.Parameters.Token] = "any-token",
                [ClientRequest.Parameters.ClientId] = ClientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
            }),
        };
        foreach (var mediaType in accept.Split(','))
            request.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse(mediaType.Trim()));

        return await http.SendAsync(request, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// A tenant holding an RSA key signs the response RS256.
    /// </summary>
    [Fact]
    public async Task ATenantWithAnRsaKey_SignsRs256()
    {
        await using var app = await StartAsync(JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature), SigningAlgorithms.RS256);

        var response = await IntrospectAsync(app);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var jwt = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var header = JsonNode.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(jwt.Split('.')[0])))!;
        Assert.Equal(SigningAlgorithms.RS256, header[JwtClaimTypes.Algorithm]!.GetValue<string>());
    }

    /// <summary>
    /// RFC 9701 section 6, introspection_encrypted_response_alg: "The default, if omitted, is that no encryption is
    /// performed". A client publishing an RSA key that names no use, and registering no introspection encryption, gets
    /// a signed JWT of three parts and not a JWE of five.
    /// </summary>
    [Fact]
    public async Task AClientPublishingAKey_WithoutRegisteredEncryption_GetsASignedJwt()
    {
        var clientKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);
        clientKey.Usage = null;
        clientKey.Algorithm = null;
        await using var app = await StartAsync(
            JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature),
            SigningAlgorithms.RS256,
            new JsonWebKeySet([clientKey.Sanitize(includePrivateKeys: false)]));

        var response = await IntrospectAsync(app);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var jwt = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(3, jwt.Split('.').Length);
    }

    /// <summary>
    /// RFC 9701 section 6, introspection_encrypted_response_alg: "If this is specified, the response will be encrypted
    /// using JWE and the configured content encryption algorithm (introspection_encrypted_response_enc)". A client
    /// registering RSA-OAEP-256 with A256GCM and publishing an RSA encryption key for it gets a JWE of five parts whose
    /// header names the registered algorithms.
    /// </summary>
    [Fact]
    public async Task AClientRegisteringEncryption_GetsAJweWithTheRegisteredAlgorithms()
    {
        var clientKey = JsonWebKeyFactory.CreateRsa(
            PublicKeyUsages.Encryption, EncryptionAlgorithms.KeyManagement.RsaOaep256);
        await using var app = await StartAsync(
            JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature),
            SigningAlgorithms.RS256,
            new JsonWebKeySet([clientKey.Sanitize(includePrivateKeys: false)]),
            keyManagementAlgorithm: EncryptionAlgorithms.KeyManagement.RsaOaep256,
            contentEncryptionAlgorithm: EncryptionAlgorithms.ContentEncryption.Aes256Gcm);

        var response = await IntrospectAsync(app);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var jwe = (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Split('.');
        Assert.Equal(5, jwe.Length);
        var header = JsonNode.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(jwe[0])))!;
        Assert.Equal(
            EncryptionAlgorithms.KeyManagement.RsaOaep256, header[JwtClaimTypes.Algorithm]!.GetValue<string>());
        Assert.Equal(
            EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
            header[JwtClaimTypes.EncryptionAlgorithm]!.GetValue<string>());
    }

    /// <summary>
    /// RFC 9110 content negotiation: where the JWT cannot be signed and the caller named JSON as acceptable too, JSON is
    /// a representation it accepts and is served; 406 is left for a caller accepting the JWT alone.
    /// </summary>
    [Fact]
    public async Task ATenantWithoutAKeyForRs256_ServesJsonWhereTheCallerAcceptsIt()
    {
        await using var app = await StartAsync(
            JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256),
            SigningAlgorithms.ES256);

        var response = await IntrospectAsync(
            app, $"{MediaTypes.TokenIntrospectionJwt}, {System.Net.Mime.MediaTypeNames.Application.Json}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(System.Net.Mime.MediaTypeNames.Application.Json, response.Content.Headers.ContentType?.MediaType);
    }

    /// <summary>
    /// RFC 9110 section 12.4.2: the quality value is a relative weight, so the representation the caller weights higher
    /// is served, and the JWT where the two weigh the same.
    /// </summary>
    [Theory]
    [InlineData(Json + ";q=1, " + Jwt + ";q=0.1", Json)]
    [InlineData(Jwt + ";q=1, " + Json + ";q=0.5", Jwt)]
    [InlineData(Jwt + ";q=0.5, " + Json + ";q=0.5", Jwt)]
    public async Task TheRepresentation_IsTheOneTheCallerWeightsHigher(string accept, string expected)
    {
        await using var app = await StartAsync(JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature), SigningAlgorithms.RS256);

        var response = await IntrospectAsync(app, accept);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(expected, response.Content.Headers.ContentType?.MediaType);
    }

    /// <summary>
    /// A registered algorithm no key of the tenant produces is a representation the server cannot supply either: ES256
    /// registered at a tenant holding an RSA key alone is answered 406, not a server error.
    /// </summary>
    [Fact]
    public async Task ARegisteredAlgorithmNoKeyProduces_AnswersNotAcceptable()
    {
        await using var app = await StartAsync(
            JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature),
            SigningAlgorithms.RS256,
            introspectionAlgorithm: SigningAlgorithms.ES256);

        var response = await IntrospectAsync(app);

        Assert.Equal(HttpStatusCode.NotAcceptable, response.StatusCode);
    }

    /// <summary>
    /// A tenant holding only a P-256 key cannot produce the default the specification names, so the request for the
    /// JWT is refused with 406, RFC 9110 section 15.5.7: the resource "does not have a current representation that
    /// would be acceptable to the user agent, according to the proactive negotiation header fields received in the
    /// request".
    /// </summary>
    [Fact]
    public async Task ATenantWithoutAKeyForRs256_AnswersNotAcceptable()
    {
        await using var app = await StartAsync(
            JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256),
            SigningAlgorithms.ES256);

        var response = await IntrospectAsync(app);

        Assert.Equal(HttpStatusCode.NotAcceptable, response.StatusCode);
    }

    /// <summary>
    /// A tenant whose keys cannot sign the response for the client - ES256 registered at a tenant holding an RSA key
    /// alone, or the RS256 default at one holding a P-256 key alone - is the server's misconfiguration, and is logged as
    /// an error where the JWT is refused, as at every other endpoint; the caller is still answered 406.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ATenantWithoutTheSigningKey_IsLoggedAsAnError(bool rsaTenant)
    {
        var logs = new LevelRecordingLoggerProvider();
        await using var app = rsaTenant
            ? await StartAsync(
                JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature),
                SigningAlgorithms.RS256,
                introspectionAlgorithm: SigningAlgorithms.ES256,
                logs: logs)
            : await StartAsync(
                JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256),
                SigningAlgorithms.ES256,
                logs: logs);

        var response = await IntrospectAsync(app);

        Assert.Equal(HttpStatusCode.NotAcceptable, response.StatusCode);
        var entry = Assert.Single(logs.Entries, entry => entry.Category == typeof(ClientJwtFormatter).FullName);
        Assert.Equal(LogLevel.Error, entry.Level);
    }
}
