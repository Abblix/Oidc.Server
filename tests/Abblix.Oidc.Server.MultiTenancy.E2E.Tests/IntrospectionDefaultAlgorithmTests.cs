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

    private static async Task<WebApplication> StartAsync(JsonWebKey signingKey, string serviceTokenAlgorithm)
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
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
                },
            ],
        }));

        var app = builder.Build();
        app.UseMultiTenancy();
        app.MapOidcEndpoints();
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task<HttpResponseMessage> IntrospectAsync(WebApplication app)
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
        request.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse(MediaTypes.TokenIntrospectionJwt));

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
}
