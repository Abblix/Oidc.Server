// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Xunit;
using AuthorizationResourceValidator = Abblix.Oidc.Server.Endpoints.Authorization.Validation.ResourceValidator;
using BackChannelResourceValidator =
    Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation.ResourceValidator;
using DeviceResourceValidator = Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation.ResourceValidator;

namespace Abblix.Oidc.Server.UnitTests.Features.ResourceIndicators;

/// <summary>
/// A client gets an access token only for a resource on its list, wherever the resource comes from: named, inferred
/// from the scopes, carried over from the grant, or the tenant's default.
/// </summary>
public class AllowedResourcesTests
{
    private const string ClientId = "client";
    private const string OrdersRead = "orders.read";
    private const string BillingRead = "billing.read";

    private static readonly Uri Orders = new("https://orders.example.com");
    private static readonly Uri Billing = new("https://billing.example.com");

    private static TenantDefinition Tenant(Uri? defaultResource = null, bool infer = false) => new TestIssuer
    {
        Resources =
        [
            new ResourceDefinition(Orders, new ScopeDefinition(OrdersRead)),
            new ResourceDefinition(Billing, new ScopeDefinition(BillingRead)),
        ],
        DefaultResourceIndicator = defaultResource,
        InferResourceFromScope = infer,
    }.ToTenant();

    private static ClientInfo Client() => new(ClientId) { AllowedResources = [Orders] };

    public static TheoryData<string> Endpoints => ["authorization-code", "authorization-token", "back-channel", "device"];

    /// <summary>
    /// The error the resource validator of <paramref name="endpoint"/> answers a request naming
    /// <paramref name="resources"/> and <paramref name="scope"/> with, or null.
    /// </summary>
    private static async Task<string?> ValidateAsync(
        string endpoint,
        TenantDefinition tenant,
        Uri[]? resources,
        params string[] scope)
    {
        var client = Client();
        var manager = SingleIssuer.ResourceManager();
        return endpoint switch
        {
            "authorization-code" or "authorization-token" => (await new AuthorizationResourceValidator(manager)
                .ValidateAsync(tenant, new AuthorizationValidationContext(new AuthorizationRequest
                {
                    ClientId = ClientId,
                    ResponseType = [endpoint == "authorization-token" ? ResponseTypes.Token : ResponseTypes.Code],
                    RedirectUri = new Uri("https://client.example.com/callback"),
                    Scope = scope,
                    Resources = resources,
                }) { ClientInfo = client }))?.Error,
            "back-channel" => (await new BackChannelResourceValidator(manager).ValidateAsync(
                tenant,
                new BackChannelAuthenticationValidationContext(
                    new BackChannelAuthenticationRequest { Scope = scope, Resources = resources },
                    new ClientRequest { ClientId = ClientId }) { ClientInfo = client }))?.Error,
            "device" => (await new DeviceResourceValidator(manager).ValidateAsync(
                tenant,
                new DeviceAuthorizationValidationContext(
                    new DeviceAuthorizationRequest { Scope = scope, Resources = resources },
                    new ClientRequest { ClientId = ClientId }) { ClientInfo = client }))?.Error,
            _ => throw new ArgumentOutOfRangeException(nameof(endpoint), endpoint, null),
        };
    }

    /// <summary>
    /// A request naming a resource on the list is served, and one naming a resource off it is refused.
    /// </summary>
    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task ANamedResource_IsHeldToTheList(string endpoint)
    {
        Assert.Null(await ValidateAsync(endpoint, Tenant(), [Orders]));
        Assert.Equal(ErrorCodes.InvalidTarget, await ValidateAsync(endpoint, Tenant(), [Billing]));
    }

    /// <summary>
    /// A resource inferred from the scopes is held to the list as a named one is.
    /// </summary>
    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task AnInferredResource_IsHeldToTheList(string endpoint)
    {
        Assert.Null(await ValidateAsync(endpoint, Tenant(infer: true), null, OrdersRead));
        Assert.Equal(ErrorCodes.InvalidTarget, await ValidateAsync(endpoint, Tenant(infer: true), null, BillingRead));
    }

    /// <summary>
    /// The tenant's default resource is refused where no later token request follows to refuse it, and left to the
    /// token endpoint where one does.
    /// </summary>
    [Theory]
    [InlineData("authorization-code", null)]
    [InlineData("authorization-token", ErrorCodes.InvalidTarget)]
    [InlineData("back-channel", ErrorCodes.InvalidTarget)]
    [InlineData("device", ErrorCodes.InvalidTarget)]
    public async Task TheDefaultResourceOffTheList_IsRefusedWhereNoTokenRequestFollows(string endpoint, string? error)
        => Assert.Equal(error, await ValidateAsync(endpoint, Tenant(defaultResource: Billing), null));

    /// <summary>
    /// At the token endpoint the access token is addressed to the resources the request names, else every resource of
    /// its grant, else the tenant's default, and each is held to the list.
    /// </summary>
    [Theory]
    [InlineData(new[] { "https://orders.example.com" }, null, null, null)]
    [InlineData(new[] { "https://billing.example.com" }, null, null, ErrorCodes.InvalidTarget)]
    [InlineData(null, new[] { "https://billing.example.com" }, null, ErrorCodes.InvalidTarget)]
    [InlineData(null, new[] { "https://orders.example.com" }, null, null)]
    [InlineData(null, null, "https://billing.example.com", ErrorCodes.InvalidTarget)]
    [InlineData(null, null, "https://orders.example.com", null)]
    [InlineData(new[] { "https://orders.example.com" }, null, "https://billing.example.com", ErrorCodes.InvalidTarget)]
    public async Task ATokenRequest_IsHeldToTheList(
        string[]? named,
        string[]? granted,
        string? defaultResource,
        string? error)
    {
        var context = new TokenValidationContext(
            new TokenRequest
            {
                GrantType = GrantTypes.RefreshToken,
                Resources = named is null ? null : Array.ConvertAll(named, uri => new Uri(uri)),
            },
            new ClientRequest { ClientId = ClientId })
        {
            ClientInfo = Client(),
            AuthorizedGrant = new AuthorizedGrant(
                new AuthSession("user", "session", DateTimeOffset.UnixEpoch, "local"),
                new AuthorizationContext(
                    ClientId,
                    [],
                    null,
                    granted is null ? null : Array.ConvertAll(granted, uri => new Uri(uri)))),
        };
        var tenant = Tenant(defaultResource: defaultResource is null ? null : new Uri(defaultResource));

        var refused = await new AllowedResourceValidator().ValidateAsync(
            tenant,
            context,
            TestContext.Current.CancellationToken);

        Assert.Equal(error, refused?.Error);
    }

    /// <summary>
    /// An audience a token request names does not spare a grant from the default resource: only a token exchange
    /// carries the audiences it names into its grant, so a code redeemed naming one still mints a token addressed to
    /// the tenant's default resource.
    /// </summary>
    [Fact]
    public async Task AnAudienceTheRequestNames_DoesNotSpareTheGrantFromTheDefaultResource()
    {
        var context = new TokenValidationContext(
            new TokenRequest { GrantType = GrantTypes.AuthorizationCode, Audiences = ["https://unrelated.example.com"] },
            new ClientRequest { ClientId = ClientId })
        {
            ClientInfo = Client(),
            AuthorizedGrant = new AuthorizedGrant(
                new AuthSession("user", "session", DateTimeOffset.UnixEpoch, "local"),
                new AuthorizationContext(ClientId, [], null)),
        };

        var refused = await new AllowedResourceValidator().ValidateAsync(
            Tenant(defaultResource: Billing),
            context,
            TestContext.Current.CancellationToken);

        Assert.Equal(ErrorCodes.InvalidTarget, refused?.Error);
    }

    /// <summary>
    /// A grant naming an audience is addressed to it rather than to the tenant's default resource, so the default
    /// off the list does not refuse it.
    /// </summary>
    [Fact]
    public async Task AGrantNamingAnAudience_IsNotAddressedToTheDefaultResource()
    {
        var context = new TokenValidationContext(
            new TokenRequest { GrantType = GrantTypes.TokenExchange, Audiences = ["orders-api"] },
            new ClientRequest { ClientId = ClientId })
        {
            ClientInfo = Client(),
            AuthorizedGrant = new AuthorizedGrant(
                new AuthSession("user", "session", DateTimeOffset.UnixEpoch, "local"),
                new AuthorizationContext(ClientId, [], null) { Audiences = ["orders-api"] }),
        };

        var refused = await new AllowedResourceValidator().ValidateAsync(
            Tenant(defaultResource: Billing),
            context,
            TestContext.Current.CancellationToken);

        Assert.Null(refused);
    }

    /// <summary>
    /// A client with no list gets a token for any registered resource, as today.
    /// </summary>
    [Fact]
    public void AClientWithNoList_MayGetATokenForAnyResource()
        => Assert.True(new ClientInfo(ClientId).MayGetTokenFor(Billing));
}
