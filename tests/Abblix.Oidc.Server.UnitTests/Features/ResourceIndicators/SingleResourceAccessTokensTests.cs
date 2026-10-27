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
/// A client whose access tokens each name one resource is refused a request that would issue one naming several,
/// where that request is the last chance to name one.
/// </summary>
public class SingleResourceAccessTokensTests
{
    private const string ClientId = "client";

    private static readonly Uri Orders = new("https://orders.example.com");
    private static readonly Uri Billing = new("https://billing.example.com");

    private static readonly TenantDefinition Tenant = new TestIssuer
    {
        Resources = [new ResourceDefinition(Orders), new ResourceDefinition(Billing)],
    }.ToTenant();

    private static ClientInfo Client(bool singleResource)
        => new(ClientId) { SingleResourceAccessTokens = singleResource };

    /// <summary>
    /// A request with no later token request to name one resource at, an authorization request returning an
    /// access token, a device authorization request or a backchannel authentication request, is refused for naming
    /// two, and served without the setting.
    /// </summary>
    [Theory]
    [InlineData("authorization-token", true, ErrorCodes.InvalidTarget)]
    [InlineData("back-channel", true, ErrorCodes.InvalidTarget)]
    [InlineData("device", true, ErrorCodes.InvalidTarget)]
    [InlineData("authorization-token", false, null)]
    [InlineData("back-channel", false, null)]
    [InlineData("device", false, null)]
    [InlineData("authorization-code", true, null)]
    public async Task ARequestNamingTwoResources_IsRefusedWhereNoTokenRequestFollows(
        string endpoint,
        bool singleResource,
        string? error)
    {
        Uri[] resources = [Orders, Billing];
        var client = Client(singleResource);

        var refused = endpoint switch
        {
            "authorization-token" or "authorization-code" => (await new AuthorizationResourceValidator(
                SingleIssuer.ResourceManager()).ValidateAsync(Tenant, new AuthorizationValidationContext(
                new AuthorizationRequest
                {
                    ClientId = ClientId,
                    ResponseType = [endpoint == "authorization-token" ? ResponseTypes.Token : ResponseTypes.Code],
                    RedirectUri = new Uri("https://client.example.com/callback"),
                    Scope = [],
                    Resources = resources,
                }) { ClientInfo = client }))?.Error,
            "back-channel" => (await new BackChannelResourceValidator(SingleIssuer.ResourceManager()).ValidateAsync(
                Tenant,
                new BackChannelAuthenticationValidationContext(
                    new BackChannelAuthenticationRequest { Scope = [], Resources = resources },
                    new ClientRequest { ClientId = ClientId }) { ClientInfo = client }))?.Error,
            "device" => (await new DeviceResourceValidator(SingleIssuer.ResourceManager()).ValidateAsync(
                Tenant,
                new DeviceAuthorizationValidationContext(
                    new DeviceAuthorizationRequest { Scope = [], Resources = resources },
                    new ClientRequest { ClientId = ClientId }) { ClientInfo = client }))?.Error,
            _ => throw new ArgumentOutOfRangeException(nameof(endpoint), endpoint, null),
        };

        Assert.Equal(error, refused);
    }

    /// <summary>
    /// An exchange naming resources as audiences counts each declared one as a resource, so naming two is refused as
    /// naming two resources is, while an audience no resource declares, absolute or not, is no resource.
    /// </summary>
    [Theory]
    [InlineData(new[] { "https://orders.example.com", "https://billing.example.com" }, ErrorCodes.InvalidTarget)]
    [InlineData(new[] { "https://orders.example.com" }, null)]
    [InlineData(new[] { "https://orders.example.com", "https://unknown.example.com" }, null)]
    public async Task AnExchangeNamingResourcesAsAudiences_CountsThemAsResources(string[] audiences, string? error)
    {
        var context = new TokenValidationContext(
            new TokenRequest { GrantType = GrantTypes.TokenExchange, Audiences = audiences },
            new ClientRequest { ClientId = ClientId })
        {
            ClientInfo = Client(singleResource: true),
            AuthorizedGrant = new AuthorizedGrant(
                new AuthSession("user", "session", DateTimeOffset.UnixEpoch, "local"),
                new AuthorizationContext(ClientId, [], null)),
        };

        var refused = await new SingleResourceValidator().ValidateAsync(
            Tenant,
            context,
            TestContext.Current.CancellationToken);

        Assert.Equal(error, refused?.Error);
    }

    /// <summary>
    /// At the token endpoint the access token names the resources the request names, else every resource of its
    /// grant: a grant for two resources is redeemed by a request naming one, and refused to one naming none or both.
    /// </summary>
    [Theory]
    [InlineData(true, 0, ErrorCodes.InvalidTarget)]
    [InlineData(true, 1, null)]
    [InlineData(true, 2, ErrorCodes.InvalidTarget)]
    [InlineData(false, 0, null)]
    [InlineData(false, 2, null)]
    public async Task ATokenRequestOfAGrantForTwoResources_IsServedNamingOne(
        bool singleResource,
        int named,
        string? error)
    {
        Uri[] granted = [Orders, Billing];
        var context = new TokenValidationContext(
            new TokenRequest { GrantType = GrantTypes.AuthorizationCode, Resources = granted[..named] },
            new ClientRequest { ClientId = ClientId })
        {
            ClientInfo = Client(singleResource),
            AuthorizedGrant = new AuthorizedGrant(
                new AuthSession("user", "session", DateTimeOffset.UnixEpoch, "local"),
                new AuthorizationContext(ClientId, [], null, granted)),
        };

        var refused = await new SingleResourceValidator().ValidateAsync(
            Tenant,
            context,
            TestContext.Current.CancellationToken);

        Assert.Equal(error, refused?.Error);
    }
}
