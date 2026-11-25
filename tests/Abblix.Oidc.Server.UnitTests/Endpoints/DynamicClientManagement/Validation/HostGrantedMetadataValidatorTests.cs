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
/// A registering client may narrow the resources, token exchange audiences and grant types the host grants it, never
/// widen them, and a host granting none lets it name none; the host's lists hold in every registration mode and for
/// an RFC 7592 update of any client, whatever trust it was stored with.
/// </summary>
public class HostGrantedMetadataValidatorTests
{
    private static readonly Uri Orders = new("https://orders.example.com");
    private static readonly Uri Billing = new("https://billing.example.com");

    private static readonly string[] SignInGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken];

    /// <summary>
    /// The ways a request reaches the step: a registration under each mode the settings open it in, and an update of
    /// a client stored with each trust.
    /// </summary>
    public enum Arrival
    {
        OpenRegistration,
        RegistrationWithAnInitialAccessToken,
        RegistrationWithATrustedStatement,
        UpdateOfAnUntrustedClient,
        UpdateOfATrustedClient,
    }

    public static TheoryData<Arrival> Arrivals => new()
    {
        Arrival.OpenRegistration,
        Arrival.RegistrationWithAnInitialAccessToken,
        Arrival.RegistrationWithATrustedStatement,
        Arrival.UpdateOfAnUntrustedClient,
        Arrival.UpdateOfATrustedClient,
    };

    private static OidcOptions SettingsFor(Arrival arrival, NewClientOptions granted) => arrival switch
    {
        Arrival.RegistrationWithAnInitialAccessToken => new OidcOptions
        {
            RequireInitialAccessToken = true,
            NewClientOptions = granted,
        },
        Arrival.RegistrationWithATrustedStatement => new OidcOptions
        {
            SoftwareStatement = new SoftwareStatementOptions
            {
                RequireSoftwareStatement = true,
                TrustedIssuers =
                [
                    new TrustedIssuer
                    {
                        Issuer = "https://statements.example.com",
                        JwksUri = new Uri("https://statements.example.com/jwks"),
                    },
                ],
            },
            NewClientOptions = granted,
        },
        Arrival.OpenRegistration or Arrival.UpdateOfAnUntrustedClient or Arrival.UpdateOfATrustedClient
            => new OidcOptions { NewClientOptions = granted },
        _ => throw new ArgumentOutOfRangeException(nameof(arrival), arrival, null),
    };

    private static ClientRegistrationValidationContext ContextFor(Arrival arrival, ClientRegistrationRequest request)
        => arrival switch
        {
            Arrival.OpenRegistration or
                Arrival.RegistrationWithAnInitialAccessToken or
                Arrival.RegistrationWithATrustedStatement => new ClientRegistrationValidationContext(request),
            Arrival.UpdateOfAnUntrustedClient => UpdateOf(request, ClientTrust.Untrusted),
            Arrival.UpdateOfATrustedClient => UpdateOf(request, ClientTrust.Trusted),
            _ => throw new ArgumentOutOfRangeException(nameof(arrival), arrival, null),
        };

    private static ClientRegistrationValidationContext UpdateOf(ClientRegistrationRequest request, ClientTrust trust)
        => new(request)
        {
            Operation = DynamicClientOperation.Update,
            StoredClient = new ClientInfo("client-1") { Trust = trust },
        };

    private static async Task<string?> ValidateAsync(
        NewClientOptions granted,
        Uri[]? allowedResources = null,
        string[]? tokenExchangeAudiences = null,
        string[]? grantTypes = null,
        Arrival arrival = Arrival.OpenRegistration)
    {
        var options = new Mock<IOptionsMonitor<OidcOptions>>();
        options.Setup(monitor => monitor.CurrentValue).Returns(SettingsFor(arrival, granted));
        var context = ContextFor(arrival, new ClientRegistrationRequest
        {
            AllowedResources = allowedResources,
            TokenExchangeAudiences = tokenExchangeAudiences,
            // RFC 7591 section 2: an omitted grant_types member means the authorization code grant, which the
            // registration model writes before any check runs
            GrantTypes = grantTypes ?? [GrantTypes.AuthorizationCode],
        });

        return (await new HostGrantedMetadataValidator(options.Object).ValidateAsync(SingleIssuer.Tenant, context))
            ?.Error;
    }

    [Fact]
    public async Task ARegistrationNamingNeither_IsServed()
        => Assert.Null(await ValidateAsync(new NewClientOptions()));

    [Fact]
    public async Task AResourceWithinTheHostsSet_IsServed()
        => Assert.Null(await ValidateAsync(new NewClientOptions { AllowedResources = [Orders, Billing] }, [Orders]));

    [Fact]
    public async Task AResourceOutsideTheHostsSet_IsRefused()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(new NewClientOptions { AllowedResources = [Orders] }, [Billing]));

    /// <summary>
    /// The host's list of resources is empty by default, so a resource is refused in every mode until the host lists
    /// it.
    /// </summary>
    [Theory]
    [MemberData(nameof(Arrivals))]
    public async Task AResourceTheDefaultListDoesNotHold_IsRefused(Arrival arrival)
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(new NewClientOptions(), [Orders], arrival: arrival));

    [Fact]
    public async Task AnAudienceOutsideTheHostsSet_IsRefused()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(
                new NewClientOptions { TokenExchangeAudiences = ["orders-api"] },
                tokenExchangeAudiences: ["billing-api"]));

    /// <summary>
    /// A value naming nothing is one the host did not grant, wherever it stands in the list, so the values after it
    /// are not let through unread.
    /// </summary>
    [Fact]
    public async Task AListLeadingWithNoValue_IsRefused()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(
                new NewClientOptions { TokenExchangeAudiences = ["orders-api"] },
                tokenExchangeAudiences: [null!, "billing-api"]));

    /// <summary>
    /// A value naming nothing is refused on its own, beside values the host grants.
    /// </summary>
    [Fact]
    public async Task ANoValueBesideAGrantedOne_IsRefused()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(
                new NewClientOptions { TokenExchangeAudiences = ["orders-api"] },
                tokenExchangeAudiences: [null!, "orders-api"]));

    [Fact]
    public async Task AnAudienceAHostGrantingNoneDidNotGrant_IsRefused()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(new NewClientOptions(), tokenExchangeAudiences: ["orders-api"]));

    /// <summary>
    /// The host's grant types are the authorization code and the refresh token by default, so a client asking for
    /// the client credentials grant is refused in every mode, a closed registration and an update of a trusted
    /// client included, while the default grants are served.
    /// </summary>
    [Theory]
    [MemberData(nameof(Arrivals))]
    public async Task UnderTheDefaultList_OnlyTheGrantsOfASignInAreServed(Arrival arrival)
    {
        Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(new NewClientOptions(), grantTypes: [GrantTypes.ClientCredentials], arrival: arrival));
        Assert.Null(await ValidateAsync(new NewClientOptions(), grantTypes: SignInGrantTypes, arrival: arrival));
    }

    /// <summary>
    /// A grant the host lists is served in every mode.
    /// </summary>
    [Theory]
    [MemberData(nameof(Arrivals))]
    public async Task AGrantTheHostLists_IsServed(Arrival arrival)
        => Assert.Null(await ValidateAsync(
            new NewClientOptions { AllowedGrantTypes = [GrantTypes.ClientCredentials] },
            grantTypes: [GrantTypes.ClientCredentials],
            arrival: arrival));

    [Fact]
    public async Task AGrantTypeOutsideTheHostsLimit_IsRefused()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(
                new NewClientOptions { AllowedGrantTypes = SignInGrantTypes },
                grantTypes: [GrantTypes.AuthorizationCode, GrantTypes.ClientCredentials]));

    /// <summary>
    /// An omitted <c>grant_types</c> member means the authorization code grant (RFC 7591 section 2), which a limit
    /// leaving it out does not admit.
    /// </summary>
    [Fact]
    public async Task AnOmittedMemberUnderALimitWithoutTheAuthorizationCodeGrant_IsRefused()
        => Assert.Equal(
            ErrorCodes.InvalidClientMetadata,
            await ValidateAsync(new NewClientOptions { AllowedGrantTypes = [GrantTypes.ClientCredentials] }));
}
