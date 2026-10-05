// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Options;
using Xunit;
using AuthorizationResourceValidator = Abblix.Oidc.Server.Endpoints.Authorization.Validation.ResourceValidator;
using BackChannelResourceValidator =
    Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation.ResourceValidator;
using DeviceResourceValidator = Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation.ResourceValidator;
using TokenResourceValidator = Abblix.Oidc.Server.Endpoints.Token.Validation.ResourceValidator;

namespace Abblix.Oidc.Server.UnitTests.Features.ResourceIndicators;

/// <summary>
/// Each endpoint taking a resource indicator infers it from the scopes of a request naming none, when the issuer
/// says so, and only then.
/// </summary>
public class ResourceValidatorsInferenceTests
{
    private const string ClientId = "client";
    private const string OrdersRead = "orders.read";
    private const string BillingRead = "billing.read";

    private static readonly Uri Orders = new("https://orders.example.com");
    private static readonly Uri Billing = new("https://billing.example.com");

    public static TheoryData<string> Endpoints => ["authorization", "back-channel", "device", "token"];

    /// <summary>
    /// The resources a request naming no resource is taken to be for at <paramref name="endpoint"/>, or the error
    /// it is refused with.
    /// </summary>
    private static async Task<(string? Error, Uri[] Resources)> ValidateAsync(
        string endpoint,
        bool infer,
        params string[] scopes)
    {
        var options = Options.Create(new OidcOptions
        {
            InferResourceFromScope = infer,
            Resources =
            [
                new ResourceDefinition(Orders, new ScopeDefinition(OrdersRead)),
                new ResourceDefinition(Billing, new ScopeDefinition(BillingRead)),
            ],
        });
        var resourceManager = SingleIssuer.ResourceManager(options);
        var inference = new ResourceInference(SingleIssuer.SettingsOf(options));
        var client = new ClientInfo(ClientId);

        switch (endpoint)
        {
            case "authorization":
            {
                var context = new AuthorizationValidationContext(new AuthorizationRequest
                {
                    ClientId = ClientId,
                    ResponseType = [ResponseTypes.Code],
                    RedirectUri = new Uri("https://client.example.com/callback"),
                    Scope = scopes,
                }) { ClientInfo = client };
                var error = await new AuthorizationResourceValidator(resourceManager, inference).ValidateAsync(context);
                return (error?.Error, Uris(context.Resources));
            }

            case "back-channel":
            {
                var context = new BackChannelAuthenticationValidationContext(
                    new BackChannelAuthenticationRequest { Scope = scopes },
                    new ClientRequest { ClientId = ClientId }) { ClientInfo = client };
                var error = await new BackChannelResourceValidator(resourceManager, inference).ValidateAsync(context);
                return (error?.Error, Uris(context.Resources));
            }

            case "device":
            {
                var context = new DeviceAuthorizationValidationContext(
                    new DeviceAuthorizationRequest { Scope = scopes },
                    new ClientRequest { ClientId = ClientId }) { ClientInfo = client };
                var error = await new DeviceResourceValidator(resourceManager, inference).ValidateAsync(context);
                return (error?.Error, Uris(context.Resources));
            }

            case "token":
            {
                var context = new TokenValidationContext(
                    new TokenRequest { Scope = scopes },
                    new ClientRequest { ClientId = ClientId });
                var error = await new TokenResourceValidator(resourceManager, inference)
                    .ValidateAsync(context, TestContext.Current.CancellationToken);
                return (error?.Error, Uris(context.Resources));
            }

            default:
                throw new ArgumentOutOfRangeException(nameof(endpoint), endpoint, "No such endpoint in this test.");
        }
    }

    private static Uri[] Uris(ResourceDefinition[] resources)
        => resources.Select(resource => resource.Resource).ToArray();

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task AScopeOfOneResource_TakesTheRequestToBeForIt(string endpoint)
    {
        var (error, resources) = await ValidateAsync(endpoint, infer: true, Scopes.OpenId, OrdersRead);

        Assert.Null(error);
        Assert.Equal([Orders], resources);
    }

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task ScopesOfTwoResources_AreRefusedAsInvalidScope(string endpoint)
    {
        var (error, _) = await ValidateAsync(endpoint, infer: true, OrdersRead, BillingRead);

        Assert.Equal(ErrorCodes.InvalidScope, error);
    }

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task WithInferenceOff_ARequestNamingNoResourceStaysWithout(string endpoint)
    {
        var (error, resources) = await ValidateAsync(endpoint, infer: false, OrdersRead, BillingRead);

        Assert.Null(error);
        Assert.Empty(resources);
    }
}
