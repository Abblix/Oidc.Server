// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// A client nobody vetted, one registering while anybody may register or updating a registration made so, gets only
/// the grant types of an interactive sign-in while the host names none, and the resources the host names, none while
/// it names none; any other client is left to the other checks. An update is judged by the trust of the client it
/// replaces, not by the settings.
/// </summary>
public class OpenRegistrationDefaultsValidatorTests
{
    private static readonly Uri Orders = new("https://orders.example.com");

    /// <summary>
    /// Where the request comes from: a registration under the settings, or an update of a client stored with a trust.
    /// </summary>
    private sealed record Arrival(DynamicClientOperation Operation, ClientTrust? StoredTrust = null)
    {
        public static readonly Arrival Registration = new(DynamicClientOperation.Register);

        public static Arrival UpdateOf(ClientTrust trust) => new(DynamicClientOperation.Update, trust);

        public ClientRegistrationValidationContext ContextFor(ClientRegistrationRequest request) => new(request)
        {
            Operation = Operation,
            StoredClient = StoredTrust is { } trust ? new ClientInfo("client-1") { Trust = trust } : null,
        };
    }

    private static OidcOptions Settings(
        bool requireInitialAccessToken,
        NewClientOptions? newClients = null,
        SoftwareStatementOptions? softwareStatement = null) => new()
    {
        RequireInitialAccessToken = requireInitialAccessToken,
        SoftwareStatement = softwareStatement ?? new SoftwareStatementOptions(),
        NewClientOptions = newClients ?? new NewClientOptions(),
    };

    /// <summary>
    /// The error the step answers <paramref name="request"/> with, and the request it leaves.
    /// </summary>
    private static async Task<(string? Error, ClientRegistrationRequest Request)> JudgeAsync(
        OidcOptions settings,
        ClientRegistrationRequest request,
        Arrival? arrival = null)
    {
        var options = new Mock<IOptionsMonitor<OidcOptions>>();
        options.Setup(monitor => monitor.CurrentValue).Returns(settings);
        var context = (arrival ?? Arrival.Registration).ContextFor(request);

        var validator = new OpenRegistrationDefaultsValidator(options.Object);
        var error = await validator.ValidateAsync(SingleIssuer.Tenant, context);
        return (error?.Error, context.Request);
    }

    private static async Task<string?> ErrorFor(OidcOptions settings, string[] grantTypes, Arrival? arrival = null)
        => (await JudgeAsync(settings, new ClientRegistrationRequest { GrantTypes = grantTypes }, arrival)).Error;

    private static async Task<Uri[]?> ResourcesAfter(
        OidcOptions settings,
        Uri[]? requested = null,
        Arrival? arrival = null)
    {
        var (error, request) = await JudgeAsync(
            settings,
            new ClientRegistrationRequest { GrantTypes = [GrantTypes.AuthorizationCode], AllowedResources = requested },
            arrival);
        Assert.Null(error);
        return request.AllowedResources;
    }

    /// <summary>
    /// A registration admitting only clients a software statement from a trusted issuer vouches for.
    /// </summary>
    private static SoftwareStatementOptions StatementRequired(bool withTrustedIssuer) => new()
    {
        RequireSoftwareStatement = true,
        TrustedIssuers = withTrustedIssuer
            ? [new TrustedIssuer { Issuer = "https://statements.example.com", JwksUri = new Uri("https://statements.example.com/jwks") }]
            : [],
    };

    [Fact]
    public async Task AGrantOutsideAnInteractiveSignIn_UnderOpenRegistrationWithoutAHostSet_IsRefused()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ErrorFor(Settings(false), [GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials]));

    [Fact]
    public async Task TheGrantsOfAnInteractiveSignIn_UnderOpenRegistrationWithoutAHostSet_AreServed()
        => Assert.Null(await ErrorFor(Settings(false), [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken]));

    [Fact]
    public async Task AnyGrant_WhenAnInitialAccessTokenIsRequired_IsLeftToTheOtherChecks()
        => Assert.Null(await ErrorFor(Settings(true), [GrantTypes.ClientCredentials]));

    [Fact]
    public async Task AnyGrant_WhenTheHostNamesTheGrantTypes_IsLeftToTheOtherChecks()
        => Assert.Null(await ErrorFor(
            Settings(false, new NewClientOptions { AllowedGrantTypes = [GrantTypes.AuthorizationCode] }),
            [GrantTypes.ClientCredentials]));

    [Fact]
    public async Task AClientNamingNoResource_UnderOpenRegistrationWithoutAHostSet_IsGivenNone()
        => Assert.Equal((Uri[]?)[], await ResourcesAfter(Settings(false)));

    [Fact]
    public async Task TheResources_WhenAnInitialAccessTokenIsRequired_AreLeftAsTheyAre()
        => Assert.Null(await ResourcesAfter(Settings(true)));

    /// <summary>
    /// The host's list is written into the request here, so the options the client is later built from never decide
    /// it.
    /// </summary>
    [Fact]
    public async Task AClientNamingNoResource_UnderOpenRegistration_IsGivenTheHostsList()
        => Assert.Equal(
            (Uri[]?)[Orders],
            await ResourcesAfter(Settings(false, new NewClientOptions { AllowedResources = [Orders] })));

    /// <summary>
    /// A client naming resources is left to the check of the host's set, which refuses them, rather than given none.
    /// </summary>
    [Fact]
    public async Task ResourcesAClientNames_AreLeftToTheHostsSetCheck()
        => Assert.Equal((Uri[]?)[Orders], await ResourcesAfter(Settings(false), [Orders]));

    /// <summary>
    /// A registration requiring a software statement from a trusted issuer is not open, whatever the initial access
    /// token setting says, so the request keeps the grant types and resources it names.
    /// </summary>
    [Fact]
    public async Task ARegistrationRequiringATrustedSoftwareStatement_IsNotHeldToTheOpenDefaults()
    {
        var settings = Settings(false, softwareStatement: StatementRequired(withTrustedIssuer: true));

        Assert.Null(await ErrorFor(settings, [GrantTypes.ClientCredentials]));
        Assert.Null(await ResourcesAfter(settings));
    }

    /// <summary>
    /// A statement required while no issuer is trusted vouches for nobody, so registration stays open.
    /// </summary>
    [Fact]
    public async Task ARegistrationRequiringAStatementNoIssuerIsTrustedFor_IsHeldToTheOpenDefaults()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ErrorFor(
                Settings(false, softwareStatement: StatementRequired(withTrustedIssuer: false)),
                [GrantTypes.ClientCredentials]));

    /// <summary>
    /// A client registered while registration was open stays one nobody vetted: once registration closes, its update
    /// still cannot ask for a grant outside an interactive sign-in, and it is still given no resource.
    /// </summary>
    [Fact]
    public async Task AnUpdateOfAnUnreviewedClient_AfterRegistrationCloses_IsHeldToTheOpenDefaults()
    {
        var closed = Settings(true);
        var update = Arrival.UpdateOf(ClientTrust.Unreviewed);

        Assert.Equal(ErrorCodes.InvalidClientMetadata, await ErrorFor(closed, [GrantTypes.ClientCredentials], update));
        Assert.Equal((Uri[]?)[], await ResourcesAfter(closed, arrival: update));
    }

    /// <summary>
    /// A client somebody let in keeps what it was given once registration opens: its update is left to the other
    /// checks.
    /// </summary>
    [Fact]
    public async Task AnUpdateOfAReviewedClient_AfterRegistrationOpens_IsLeftToTheOtherChecks()
    {
        var open = Settings(false);
        var update = Arrival.UpdateOf(ClientTrust.Reviewed);

        Assert.Null(await ErrorFor(open, [GrantTypes.ClientCredentials], update));
        Assert.Null(await ResourcesAfter(open, arrival: update));
    }
}
