// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.JwtBearer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// RFC 10070 section 4, case A: the authorization server of a JWT bearer authorization grant "MAY be identified by
/// either its issuer identifier or its token endpoint URL". The token endpoint URL is the one on the issuer's own
/// scheme, host and port, never the host a request names: a tenant is found by its host alone, port and case aside,
/// so a request carrying another port or another case of the host still reaches it, and taken from that request the
/// URL would match an assertion minted for another service on the same host.
/// </summary>
public sealed class JwtBearerGrantAudienceTests
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string TokenPath = "/connect/token";
    private const string ClientId = "bearer-client";
    private const string ClientSecret = "bearer-client-secret";
    private const string AssertionIssuer = "https://idp.example.com";

    private const string AnotherPort = "auth.example.com:8443";
    private const string AnotherCase = "AUTH.example.com";
    private const string MtlsBase = "https://mtls.example.com";
    private const string MtlsHostWithAnotherPort = "mtls.example.com:8443";

    private static readonly RsaJsonWebKey AssertionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    /// <summary>
    /// Each request reaches the tenant with a host spelled otherwise than its issuer. An assertion naming the token
    /// endpoint as that request spells it is refused as an invalid grant, under either audience policy; the same
    /// request with the assertion naming the token endpoint on the issuer's authority, or the issuer itself, is issued a
    /// token, so the refusal is the audience's and not the tenant's or the endpoint's.
    /// </summary>
    [Theory]
    [InlineData(AnotherPort, true)]
    [InlineData(AnotherPort, false)]
    [InlineData(AnotherCase, true)]
    [InlineData(AnotherCase, false)]
    public async Task TheTokenEndpointAsTheRequestSpellsIt_IsNotThisServer(string requestHost, bool strict)
    {
        await using var app = await StartAsync(strict);

        using var refused = await GrantAsync(app, requestHost, $"https://{requestHost}{Acme}{TokenPath}");
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(ErrorCodes.InvalidGrant, await ErrorResponseReader.ErrorCodeOf(refused));

        using var onTheIssuersAuthority = await GrantAsync(app, requestHost, Host + Acme + TokenPath);
        Assert.Equal(HttpStatusCode.OK, onTheIssuersAuthority.StatusCode);

        using var theIssuer = await GrantAsync(app, requestHost, Host + Acme);
        Assert.Equal(HttpStatusCode.OK, theIssuer.StatusCode);
    }

    /// <summary>
    /// The application base URI the permissive policy once accepted was the tenant's issuer as the request spells it,
    /// so it names this server only where it is the issuer: spelled with the request's other port it is refused under
    /// either policy.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TheApplicationUriAsTheRequestSpellsIt_IsNotThisServer(bool strict)
    {
        await using var app = await StartAsync(strict);

        using var refused = await GrantAsync(app, AnotherPort, $"https://{AnotherPort}{Acme}");

        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(ErrorCodes.InvalidGrant, await ErrorResponseReader.ErrorCodeOf(refused));
    }

    /// <summary>
    /// Discovery fetched with another port in the Host header publishes the token endpoint on the issuer's authority,
    /// under the tenant's path, and an assertion naming the URL the document publishes is issued a token: a client
    /// following the document and RFC 10070 section 4 case A is not refused.
    /// </summary>
    [Fact]
    public async Task TheTokenEndpointDiscoveryPublishes_IsAcceptedWhateverHostTheDocumentWasFetchedOn()
    {
        await using var app = await StartAsync(strict: true);
        using var http = app.GetTestClient();
        http.BaseAddress = new Uri(Host);
        using var discoveryRequest = new HttpRequestMessage(HttpMethod.Get, Acme + "/.well-known/openid-configuration");
        discoveryRequest.Headers.Host = AnotherPort;

        using var discovery = await http.SendAsync(discoveryRequest, TestContext.Current.CancellationToken);
        discovery.EnsureSuccessStatusCode();
        var document = JsonNode.Parse(await discovery.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        var tokenEndpoint = document[ConfigurationResponse.Parameters.TokenEndpoint]!.GetValue<string>();
        Assert.Equal(Host + Acme + TokenPath, tokenEndpoint);

        using var granted = await GrantAsync(app, AnotherPort, tokenEndpoint);
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
    }

    /// <summary>
    /// A grant requested at the tenant's mutual-TLS alias, which RFC 8705 section 5 has a client doing mutual TLS use in
    /// preference to the ordinary endpoint, may name that alias as the token endpoint URL; spelled with the port the
    /// request names it is refused.
    /// </summary>
    [Theory]
    [InlineData(MtlsBase + Acme + TokenPath, HttpStatusCode.OK)]
    [InlineData("https://" + MtlsHostWithAnotherPort + Acme + TokenPath, HttpStatusCode.BadRequest)]
    public async Task TheMutualTlsAlias_IsTheTokenEndpointOnItsOwnAuthority(string audience, HttpStatusCode expected)
    {
        await using var app = await StartAsync(strict: true, mtlsBaseUri: new Uri(MtlsBase));

        using var response = await GrantAsync(app, MtlsHostWithAnotherPort, audience);

        Assert.Equal(expected, response.StatusCode);
    }

    private static async Task<WebApplication> StartAsync(bool strict, Uri? mtlsBaseUri = null)
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services.AddSingleton<IJwtBearerIssuerProvider, InlineKeyIssuerProvider>();
        builder.Services.AddOidcServices(options =>
        {
            options.EnabledEndpoints = OidcEndpoints.Base;
            // The obsolete setting is set to show that neither value changes what is accepted
#pragma warning disable CS0618
            options.JwtBearer = new JwtBearerOptions
            {
                StrictAudienceValidation = strict,
                TrustedIssuers = [new TrustedIssuer { Issuer = AssertionIssuer, JwksUri = new Uri(AssertionIssuer + "/jwks") }],
            };
#pragma warning restore CS0618
            options.Tenants.Add(new TenantDefinition
            {
                Id = "acme",
                Issuer = new Uri(Host + Acme),
                MtlsBaseUri = mtlsBaseUri,
                SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
                Clients =
                [
                    new ClientInfo(ClientId)
                    {
                        ClientSecrets =
                        [
                            new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)) },
                        ],
                        TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
                        AllowedGrantTypes = [GrantTypes.JwtBearer],
                    },
                ],
            });
        });

        var app = builder.Build();
        app.UseMultiTenancy();
        app.UseCors();
        app.MapOidcEndpoints();
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    /// <summary>
    /// A JWT bearer grant request sent with <paramref name="requestHost"/> in its Host header, carrying an assertion of
    /// the trusted issuer addressed to <paramref name="audience"/> alone.
    /// </summary>
    private static async Task<HttpResponseMessage> GrantAsync(WebApplication app, string requestHost, string audience)
    {
        var now = TimeProvider.System.GetUtcNow();
        var assertion = await app.Services.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(
            new JsonWebToken
            {
                Header = { Algorithm = SigningAlgorithms.RS256, KeyId = AssertionKey.KeyId },
                Payload =
                {
                    Issuer = AssertionIssuer,
                    Subject = "user-1",
                    Audiences = [audience],
                    JwtId = Guid.NewGuid().ToString("N"),
                    IssuedAt = now,
                    ExpiresAt = now.AddMinutes(5),
                },
            },
            AssertionKey);

        using var http = app.GetTestClient();
        http.BaseAddress = new Uri(Host);
        using var request = new HttpRequestMessage(HttpMethod.Post, Acme + TokenPath)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [TokenRequest.Parameters.GrantType] = GrantTypes.JwtBearer,
                [TokenRequest.Parameters.Assertion] = assertion,
                [ClientRequest.Parameters.ClientId] = ClientId,
                [ClientRequest.Parameters.ClientSecret] = ClientSecret,
            }),
        };
        request.Headers.Host = requestHost;
        return await http.SendAsync(request, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// The trusted issuers configured, with the assertion key held in memory in place of the issuer's JWKS URI: a host
    /// answering the issuer's keys its own way.
    /// </summary>
    private sealed class InlineKeyIssuerProvider(IOptionsMonitor<OidcOptions> options) : IJwtBearerIssuerProvider
    {
        public JwtBearerOptions Options => options.CurrentValue.JwtBearer;

        public Task<bool> IsTrustedIssuerAsync(TenantDefinition tenant, string issuer)
            => Task.FromResult(issuer == AssertionIssuer);

        public Task<TrustedIssuer?> GetTrustedIssuerAsync(TenantDefinition tenant, string issuer)
            => Task.FromResult(Options.TrustedIssuers.FirstOrDefault(trusted => trusted.Issuer == issuer));

        public IAsyncEnumerable<JsonWebKey> GetSigningKeysAsync(
            TenantDefinition tenant, string issuer, bool refetch = false)
            => (issuer == AssertionIssuer
                ? new JsonWebKey[] { AssertionKey.Sanitize(includePrivateKeys: false) }
                : []).ToAsyncEnumerable();
    }
}
