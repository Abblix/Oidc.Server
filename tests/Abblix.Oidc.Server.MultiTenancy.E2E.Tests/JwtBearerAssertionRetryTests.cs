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
/// RFC 7523 section 3 lets the authorization server refuse an assertion it has already seen, so the assertion's jti
/// is recorded as used. A request refused for something the client can correct - a scope the issuer does not allow,
/// a resource the client may not be issued a token for - is refused before that record is made, and the corrected
/// request presenting the same assertion is issued a token; an assertion a token was issued for is still refused.
/// </summary>
public sealed class JwtBearerAssertionRetryTests
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string TokenPath = "/connect/token";
    private const string ClientSecret = "bearer-client-secret";
    private const string AssertionIssuer = "https://idp.example.com";

    private const string AnyResourceClient = "any-resource-client";
    private const string SingleResourceClient = "single-resource-client";
    private const string OneResourceAllowedClient = "one-resource-allowed-client";

    private static readonly Uri Orders = new("https://orders.example.com");
    private static readonly Uri Billing = new("https://billing.example.com");
    private static readonly Uri Ledger = new("https://ledger.example.com");
    private static readonly Uri Payments = new("https://payments.example.com");
    private static readonly Uri Archive = new("https://archive.example.com");

    private static readonly RsaJsonWebKey AssertionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    /// <summary>
    /// A scope outside the issuer's allowed ones is refused as an invalid scope, and the same assertion naming the
    /// allowed scope is then issued a token.
    /// </summary>
    [Fact]
    public async Task AnAssertionRefusedAScopeItsIssuerDoesNotAllow_IsGrantedTheAllowedOne()
    {
        await using var app = await StartAsync();
        var assertion = await IssueAssertionAsync(app);

        using var refused = await PostGrantAsync(app, AnyResourceClient, assertion, Scopes.Profile);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(ErrorCodes.InvalidScope, await ErrorResponseReader.ErrorCodeOf(refused));

        using var granted = await PostGrantAsync(app, AnyResourceClient, assertion, Scopes.OpenId);
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
    }

    /// <summary>
    /// A client whose access tokens each name one resource naming two is refused as an invalid target, and the same
    /// assertion naming one of them is then issued a token.
    /// </summary>
    [Fact]
    public async Task AnAssertionRefusedTwoResourcesForASingleResourceClient_IsGrantedOne()
    {
        await using var app = await StartAsync();
        var assertion = await IssueAssertionAsync(app);

        using var refused = await PostGrantAsync(app, SingleResourceClient, assertion, resources: [Orders, Billing]);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(ErrorCodes.InvalidTarget, await ErrorResponseReader.ErrorCodeOf(refused));

        using var granted = await PostGrantAsync(app, SingleResourceClient, assertion, resources: [Orders]);
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
    }

    /// <summary>
    /// A resource the client may not be issued a token for is refused as an invalid target, and the same assertion
    /// naming the resource it may have is then issued a token.
    /// </summary>
    [Fact]
    public async Task AnAssertionRefusedAResourceTheClientMayNotHave_IsGrantedTheAllowedOne()
    {
        await using var app = await StartAsync();
        var assertion = await IssueAssertionAsync(app);

        using var refused = await PostGrantAsync(app, OneResourceAllowedClient, assertion, resources: [Billing]);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(ErrorCodes.InvalidTarget, await ErrorResponseReader.ErrorCodeOf(refused));

        using var granted = await PostGrantAsync(app, OneResourceAllowedClient, assertion, resources: [Orders]);
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
    }

    /// <summary>
    /// Two resources each publishing an encryption key are refused as an invalid target, since an encrypted token has
    /// one recipient, and the same assertion naming one of them is then issued a token.
    /// </summary>
    [Fact]
    public async Task AnAssertionRefusedTwoResourcesEachPublishingAKey_IsGrantedOne()
    {
        await using var app = await StartAsync();
        var assertion = await IssueAssertionAsync(app);

        using var refused = await PostGrantAsync(app, AnyResourceClient, assertion, resources: [Ledger, Payments]);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(ErrorCodes.InvalidTarget, await ErrorResponseReader.ErrorCodeOf(refused));

        using var granted = await PostGrantAsync(app, AnyResourceClient, assertion, resources: [Ledger]);
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
    }

    /// <summary>
    /// A resource publishing only keys no token can be encrypted to is refused as an invalid target, and the same
    /// assertion naming another resource is then issued a token.
    /// </summary>
    [Fact]
    public async Task AnAssertionRefusedAResourceItsTokenCannotBeEncryptedTo_IsGrantedAnother()
    {
        await using var app = await StartAsync();
        var assertion = await IssueAssertionAsync(app);

        using var refused = await PostGrantAsync(app, AnyResourceClient, assertion, resources: [Archive]);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(ErrorCodes.InvalidTarget, await ErrorResponseReader.ErrorCodeOf(refused));

        using var granted = await PostGrantAsync(app, AnyResourceClient, assertion, resources: [Orders]);
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
    }

    /// <summary>
    /// An assertion a token was issued for is refused as an invalid grant when presented again.
    /// </summary>
    [Fact]
    public async Task AnAssertionATokenWasIssuedFor_IsRefusedTheSecondTime()
    {
        await using var app = await StartAsync();
        var assertion = await IssueAssertionAsync(app);

        using var granted = await PostGrantAsync(app, AnyResourceClient, assertion, Scopes.OpenId);
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);

        using var replayed = await PostGrantAsync(app, AnyResourceClient, assertion, Scopes.OpenId);
        Assert.Equal(HttpStatusCode.BadRequest, replayed.StatusCode);
        Assert.Equal(ErrorCodes.InvalidGrant, await ErrorResponseReader.ErrorCodeOf(replayed));
    }

    /// <summary>
    /// Requests presenting one assertion at once, each of which would be issued a token alone, are issued exactly
    /// one: the others are refused as an invalid grant.
    /// </summary>
    [Fact]
    public async Task AnAssertionPresentedByConcurrentRequests_IsGrantedOnce()
    {
        const int requests = 8;
        await using var app = await StartAsync();
        var assertion = await IssueAssertionAsync(app);

        var responses = await Task.WhenAll(Enumerable.Range(0, requests)
            .Select(_ => PostGrantAsync(app, AnyResourceClient, assertion, Scopes.OpenId)));
        try
        {
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.OK);
            foreach (var refused in responses.Where(response => response.StatusCode != HttpStatusCode.OK))
                Assert.Equal(ErrorCodes.InvalidGrant, await ErrorResponseReader.ErrorCodeOf(refused));
        }
        finally
        {
            foreach (var response in responses)
                response.Dispose();
        }
    }

    private static async Task<WebApplication> StartAsync()
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
#pragma warning disable CS0618
            options.JwtBearer = new JwtBearerOptions
            {
                TrustedIssuers =
                [
                    new TrustedIssuer
                    {
                        Issuer = AssertionIssuer,
                        JwksUri = new Uri(AssertionIssuer + "/jwks"),
                        AllowedScopes = [Scopes.OpenId],
                    },
                ],
            };
#pragma warning restore CS0618
            options.Tenants.Add(new TenantDefinition
            {
                Id = "acme",
                Issuer = new Uri(Host + Acme),
                SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
                Resources =
                [
                    new ResourceDefinition(Orders),
                    new ResourceDefinition(Billing),
                    PublishingAKey(Ledger, EncryptionAlgorithms.KeyManagement.RsaOaep256),
                    PublishingAKey(Payments, EncryptionAlgorithms.KeyManagement.RsaOaep256),
                    PublishingAKey(Archive, SigningAlgorithms.RS256),
                ],
                Clients =
                [
                    BearerClient(AnyResourceClient),
                    BearerClient(SingleResourceClient, client => client.SingleResourceAccessTokens = true),
                    BearerClient(OneResourceAllowedClient, client => client.AllowedResources = [Orders]),
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
    /// A resource publishing one key declaring <paramref name="algorithm"/>: a key management algorithm a token is
    /// encrypted to it under, or a signing one nothing can be encrypted under.
    /// </summary>
    private static ResourceDefinition PublishingAKey(Uri resource, string algorithm)
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);
        key.Algorithm = algorithm;
        return new ResourceDefinition(resource) { Jwks = new JsonWebKeySet([key.Sanitize(includePrivateKeys: false)]) };
    }

    private static ClientInfo BearerClient(string clientId, Action<ClientInfo>? configure = null)
    {
        var client = new ClientInfo(clientId)
        {
            ClientSecrets =
            [
                new ClientSecret { Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(ClientSecret)) },
            ],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
            AllowedGrantTypes = [GrantTypes.JwtBearer],
        };
        configure?.Invoke(client);
        return client;
    }

    /// <summary>An assertion of the trusted issuer addressed to the tenant, carrying a jti of its own.</summary>
    private static async Task<string> IssueAssertionAsync(WebApplication app)
    {
        var now = TimeProvider.System.GetUtcNow();
        return await app.Services.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(
            new JsonWebToken
            {
                Header = { Algorithm = SigningAlgorithms.RS256, KeyId = AssertionKey.KeyId },
                Payload =
                {
                    Issuer = AssertionIssuer,
                    Subject = "user-1",
                    Audiences = [Host + Acme],
                    JwtId = Guid.NewGuid().ToString("N"),
                    IssuedAt = now,
                    ExpiresAt = now.AddMinutes(5),
                },
            },
            AssertionKey);
    }

    /// <summary>
    /// A JWT bearer grant request of <paramref name="clientId"/> presenting <paramref name="assertion"/>, naming
    /// <paramref name="scope"/> and <paramref name="resources"/> when given.
    /// </summary>
    private static async Task<HttpResponseMessage> PostGrantAsync(
        WebApplication app, string clientId, string assertion, string? scope = null, Uri[]? resources = null)
    {
        var form = new List<KeyValuePair<string, string>>
        {
            new(TokenRequest.Parameters.GrantType, GrantTypes.JwtBearer),
            new(TokenRequest.Parameters.Assertion, assertion),
            new(ClientRequest.Parameters.ClientId, clientId),
            new(ClientRequest.Parameters.ClientSecret, ClientSecret),
        };
        if (scope is not null)
            form.Add(new(TokenRequest.Parameters.Scope, scope));
        foreach (var resource in resources ?? [])
            form.Add(new(TokenRequest.Parameters.Resource, resource.OriginalString));

        using var http = app.GetTestClient();
        http.BaseAddress = new Uri(Host);
        using var content = new FormUrlEncodedContent(form);
        return await http.PostAsync(Acme + TokenPath, content, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// The trusted issuers configured, with the assertion key held in memory in place of the issuer's JWKS URI.
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
