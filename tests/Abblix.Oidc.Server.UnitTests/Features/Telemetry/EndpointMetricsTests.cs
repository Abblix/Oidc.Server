// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

// The tenant a measurement names comes from the multi-tenancy feature
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// Each request of an endpoint, each token handed out, each signing and each refusal for a spent budget or by the
/// license is recorded once into the server's meter, with attributes from their closed sets.
/// </summary>
public sealed class EndpointMetricsTests : IDisposable
{
    private readonly ServiceProvider _services = new ServiceCollection().AddMetrics().BuildServiceProvider();
    private readonly OidcInstruments _instruments;
    private readonly MeasurementRecorder _measured;
    private readonly RecordingLoggerFactory _logs = new();

    public EndpointMetricsTests()
    {
        var factory = _services.GetRequiredService<IMeterFactory>();
        _measured = new MeasurementRecorder(factory);
        _instruments = new OidcInstruments(_logs, factory);
    }

    public void Dispose()
    {
        _measured.Dispose();
        _services.Dispose();
    }

    private Task<Result<TokenIssued, OidcError>> Token(
        Result<TokenIssued, OidcError> result,
        ITenantAccessor? tenants = null)
        => EndpointObservation.RunAsync(
            TelemetryEndpoints.Token, _instruments, tenants, () => Task.FromResult(result), EndpointObservation.ErrorOf);

    private static TokenIssued Issued => new(
        new EncodedJsonWebToken(new JsonWebToken(), "token"),
        TokenTypes.Bearer,
        TimeSpan.FromMinutes(5),
        TokenTypeIdentifiers.AccessToken);

    private static EncodedJsonWebToken AToken => new(new JsonWebToken(), "token");

    [Fact]
    public async Task AServedRequest_IsMeasuredAsASuccess()
    {
        await Token(Issued);

        var request = Assert.Single(_measured.Of(OidcMetrics.RequestDuration));
        Assert.Equal(TelemetryEndpoints.Token, request[TelemetryTags.Endpoint]);
        Assert.Equal(TelemetryOutcomes.Success, request[TelemetryTags.Outcome]);
        Assert.False(request.ContainsKey(TelemetryTags.Error));
        Assert.False(request.ContainsKey(TelemetryTags.Tenant));
        Assert.True(Assert.Single(_measured.ValuesOf(OidcMetrics.RequestDuration)) >= 0);
    }

    [Fact]
    public async Task ARefusedRequest_IsMeasuredWithItsErrorCode()
    {
        await Token(new OidcError(ErrorCodes.InvalidGrant, "The code has expired"));

        var request = Assert.Single(_measured.Of(OidcMetrics.RequestDuration));
        Assert.Equal(TelemetryOutcomes.Refused, request[TelemetryTags.Outcome]);
        Assert.Equal(ErrorCodes.InvalidGrant, request[TelemetryTags.Error]);
        Assert.Empty(_measured.Of(OidcMetrics.RateLimitRefusals));
    }

    [Fact]
    public async Task ARefusedRequest_IsLoggedWithTheCodeItsMeasurementNames()
    {
        await Token(new OidcError("a_code_of_the_host", "Refused"));

        var logged = Assert.Single(_logs.Entries, entry => entry.EventId.Id == LogEvents.Telemetry.OidcInstruments.RequestRefused);
        Assert.Equal(LogLevel.Debug, logged.Level);
        Assert.Equal(TelemetryEndpoints.Token, logged.Value("Endpoint"));
        Assert.Equal(Assert.Single(_measured.Of(OidcMetrics.RequestDuration))[TelemetryTags.Error], logged.Value("Error"));
    }

    [Fact]
    public async Task AServedRequest_IsNotLogged()
    {
        await Token(Issued);

        Assert.DoesNotContain(_logs.Entries, entry => entry.EventId.Id == LogEvents.Telemetry.OidcInstruments.RequestRefused);
    }

    [Fact]
    public async Task AFailedRequest_IsMeasuredAsFailedAndPassesOn()
    {
        await Assert.ThrowsAsync<TimeoutException>(() => EndpointObservation.RunAsync<Result<TokenIssued, OidcError>>(
            TelemetryEndpoints.Token, _instruments, null, () => throw new TimeoutException(), EndpointObservation.ErrorOf));

        var request = Assert.Single(_measured.Of(OidcMetrics.RequestDuration));
        Assert.Equal(TelemetryOutcomes.Failed, request[TelemetryTags.Outcome]);
        Assert.Empty(_measured.Of(OidcMetrics.LicenseRefusals));
    }

    [Fact]
    public async Task UnderMultiTenancy_TheRequestNamesTheTenant()
    {
        var served = new TenantContext { Tenant = new TenantDefinition { Id = "acme", Issuer = "https://acme.example.com" } };

        await Token(Issued, Mock.Of<ITenantAccessor>(accessor => accessor.Current == served));

        Assert.Equal("acme", Assert.Single(_measured.Of(OidcMetrics.RequestDuration))[TelemetryTags.Tenant]);
    }

    [Theory]
    [InlineData(CallerRateLimiters.AuthenticationFailures, CallerRateLimiters.AuthenticationFailures)]
    [InlineData(CallerRateLimiters.Introspection, CallerRateLimiters.Introspection)]
    [InlineData("a-budget-of-the-host", TelemetryTags.Other)]
    public async Task ASpentBudget_IsCountedUnderTheEndpointAndTheBudget(string budget, string counted)
    {
        await Token(new TooManyRequestsError("Too many", RetryAfter: null, budget));

        var refusal = Assert.Single(_measured.Of(OidcMetrics.RateLimitRefusals));
        Assert.Equal(TelemetryEndpoints.Token, refusal[TelemetryTags.Endpoint]);
        Assert.Equal(counted, refusal[TelemetryTags.RateLimitBudget]);
    }

    [Fact]
    public async Task SpentAuthenticationFailures_AreCountedAsARefusalAndPassOn()
    {
        var spent = new TooManyRequestsError("Too many", RetryAfter: null, CallerRateLimiters.AuthenticationFailures);

        await Assert.ThrowsAsync<TooManyAuthenticationFailuresException>(
            () => EndpointObservation.RunAsync<Result<TokenIssued, OidcError>>(
                TelemetryEndpoints.Token,
                _instruments,
                null,
                () => throw new TooManyAuthenticationFailuresException(spent),
                EndpointObservation.ErrorOf));

        var request = Assert.Single(_measured.Of(OidcMetrics.RequestDuration));
        Assert.Equal(TelemetryOutcomes.Refused, request[TelemetryTags.Outcome]);
        Assert.Equal(ErrorCodes.TemporarilyUnavailable, request[TelemetryTags.Error]);
        var refusal = Assert.Single(_measured.Of(OidcMetrics.RateLimitRefusals));
        Assert.Equal(CallerRateLimiters.AuthenticationFailures, refusal[TelemetryTags.RateLimitBudget]);
        var logged = Assert.Single(_logs.Entries, entry => entry.EventId.Id == LogEvents.Telemetry.OidcInstruments.RequestRefused);
        Assert.Equal(ErrorCodes.TemporarilyUnavailable, logged.Value("Error"));
    }

    [Theory]
    [InlineData(LicenseRefusalReasons.IssuerNotAllowed)]
    [InlineData(LicenseRefusalReasons.IssuerLimit)]
    [InlineData(LicenseRefusalReasons.ClientLimit)]
    public async Task ALicenseRefusal_IsCountedByItsReasonAndPassesOn(string reason)
    {
        await Assert.ThrowsAnyAsync<InvalidOperationException>(
            () => EndpointObservation.RunAsync<Result<TokenIssued, OidcError>>(
                TelemetryEndpoints.Token,
                _instruments,
                null,
                () => throw new LicenseViolationException(reason),
                EndpointObservation.ErrorOf));

        var refusal = Assert.Single(_measured.Of(OidcMetrics.LicenseRefusals));
        Assert.Equal(reason, refusal[TelemetryTags.LicenseRefusalReason]);
        Assert.Single(refusal);
    }

    private static ValidTokenRequest ValidRequest(string grantType) => new(
        new TokenRequest { GrantType = grantType },
        new AuthorizedGrant(
            new AuthSession("subject", "session-1", DateTimeOffset.UnixEpoch, "idp"),
            new AuthorizationContext("client-1", [Scopes.OpenId], null)),
        new ClientInfo("client-1"),
        [],
        []);

    [Fact]
    public async Task AProcessedTokenRequest_CountsEachTokenItHandsOut()
    {
        var inner = new Mock<ITokenRequestProcessor>();
        inner
            .Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()))
            .ReturnsAsync(Issued with { IdToken = AToken, RefreshToken = AToken });
        var measured = new MeasuredTokenRequestProcessor(inner.Object, _instruments, Grants);

        // A CIBA push delivery mints its tokens through the processor with no request to the token endpoint
        await measured.ProcessAsync(ValidRequest(GrantTypes.Ciba));

        var issued = _measured.Of(OidcMetrics.TokensIssued);
        Assert.Equal(
            [TelemetryTokenTypes.AccessToken, TelemetryTokenTypes.IdToken, TelemetryTokenTypes.RefreshToken],
            issued.Select(tags => tags[TelemetryTags.TokenType]));
        Assert.All(issued, tags => Assert.Equal(GrantTypes.Ciba, tags[TelemetryTags.GrantType]));
    }

    private static IAuthorizationGrantHandler Grants => Mock.Of<IAuthorizationGrantHandler>(
        g => g.GrantTypesSupported == new[] { GrantTypes.AuthorizationCode, GrantTypes.Ciba });

    private static Mock<ITokenRequestProcessor> Issuing()
    {
        var inner = new Mock<ITokenRequestProcessor>();
        inner.Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>())).ReturnsAsync(Issued);
        return inner;
    }

    [Fact]
    public async Task AGrantTypeTheServerDoesNotSupportAsSpelled_IsNotNamed()
    {
        var measured = new MeasuredTokenRequestProcessor(Issuing().Object, _instruments, Grants);

        await measured.ProcessAsync(ValidRequest("Authorization_Code"));

        Assert.False(Assert.Single(_measured.Of(OidcMetrics.TokensIssued)).ContainsKey(TelemetryTags.GrantType));
    }

    [Fact]
    public async Task UnderMultiTenancy_ATokenNamesTheTenant()
    {
        var served = new TenantContext { Tenant = new TenantDefinition { Id = "acme", Issuer = "https://acme.example.com" } };
        var measured = new MeasuredTokenRequestProcessor(
            Issuing().Object, _instruments, Grants, Mock.Of<ITenantAccessor>(accessor => accessor.Current == served));

        await measured.ProcessAsync(ValidRequest(GrantTypes.AuthorizationCode));

        Assert.Equal("acme", Assert.Single(_measured.Of(OidcMetrics.TokensIssued))[TelemetryTags.Tenant]);
    }

    [Fact]
    public async Task ARefusedTokenRequest_CountsNoToken()
    {
        var inner = new Mock<ITokenRequestProcessor>();
        inner
            .Setup(p => p.ProcessAsync(It.IsAny<ValidTokenRequest>()))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidGrant, "The code has expired"));
        var measured = new MeasuredTokenRequestProcessor(inner.Object, _instruments, Grants);

        await measured.ProcessAsync(ValidRequest(GrantTypes.AuthorizationCode));

        Assert.Empty(_measured.Of(OidcMetrics.TokensIssued));
    }

    [Fact]
    public async Task AnAuthorizationResponse_CountsItsTokensUnderTheImplicitGrant()
    {
        var request = new AuthorizationRequest();
        var inner = new Mock<IAuthorizationHandler>();
        inner
            .Setup(h => h.HandleAsync(request))
            .ReturnsAsync(new SuccessfullyAuthenticated(request, ResponseModes.Fragment, null, [])
            {
                AccessToken = AToken,
                IdToken = AToken,
            });
        var traced = new ObservedAuthorizationHandler(inner.Object, _instruments);

        await traced.HandleAsync(request);

        var issued = _measured.Of(OidcMetrics.TokensIssued);
        Assert.Equal(
            [TelemetryTokenTypes.AccessToken, TelemetryTokenTypes.IdToken],
            issued.Select(tags => tags[TelemetryTags.TokenType]));
        Assert.All(issued, tags => Assert.Equal(GrantTypes.Implicit, tags[TelemetryTags.GrantType]));
    }

    [Fact]
    public async Task ARegistration_IsCountedByHowItWasAnswered()
    {
        var inner = new Mock<IRegisterClientHandler>();
        inner
            .SetupSequence(h => h.HandleAsync(It.IsAny<ClientRegistrationRequest>()))
            .ReturnsAsync(new ClientRegistrationSuccessResponse("client", null, "token"))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidRedirectUri, "Refused"));
        var traced = new ObservedRegisterClientHandler(inner.Object, _instruments);

        await traced.HandleAsync(new ClientRegistrationRequest());
        await traced.HandleAsync(new ClientRegistrationRequest());

        Assert.Equal(
            [TelemetryOutcomes.Success, TelemetryOutcomes.Refused],
            _measured.Of(OidcMetrics.ClientsRegistered).Select(tags => tags[TelemetryTags.Outcome]));
    }

    [Fact]
    public async Task ARegistrationEndingInAnException_IsCountedAsFailedAndPassesOn()
    {
        var inner = new Mock<IRegisterClientHandler>();
        inner
            .Setup(h => h.HandleAsync(It.IsAny<ClientRegistrationRequest>()))
            .ThrowsAsync(new TimeoutException());
        var traced = new ObservedRegisterClientHandler(inner.Object, _instruments);

        await Assert.ThrowsAsync<TimeoutException>(() => traced.HandleAsync(new ClientRegistrationRequest()));

        Assert.Equal(
            TelemetryOutcomes.Failed,
            Assert.Single(_measured.Of(OidcMetrics.ClientsRegistered))[TelemetryTags.Outcome]);
    }

    [Theory]
    [InlineData(SigningAlgorithms.RS256, SigningAlgorithms.RS256)]
    [InlineData(null, TelemetryTags.Other)]
    public async Task ASigning_IsMeasuredUnderTheAlgorithmTheSignerSettled(string? settled, string measured)
    {
        var inner = new Mock<IJsonWebTokenSigner>();
        inner
            .Setup(s => s.SignAsync(It.IsAny<JsonWebToken>(), It.IsAny<JsonWebKey?>(), It.IsAny<CancellationToken>()))
            .Callback<JsonWebToken, JsonWebKey?, CancellationToken>((token, _, _) => token.Header.Algorithm = settled)
            .ReturnsAsync("jws");
        var signer = new MeasuredJsonWebTokenSigner(inner.Object, _instruments);

        Assert.Equal("jws", await signer.SignAsync(new JsonWebToken(), SigningKey, TestContext.Current.CancellationToken));

        var signing = Assert.Single(_measured.Of(OidcMetrics.TokenSigningDuration));
        Assert.Equal(measured, signing[TelemetryTags.SigningAlgorithm]);
    }

    [Fact]
    public async Task ATokenLeftUnsigned_IsNotMeasured()
    {
        var inner = new Mock<IJsonWebTokenSigner>();
        inner
            .Setup(s => s.SignAsync(It.IsAny<JsonWebToken>(), null, It.IsAny<CancellationToken>()))
            .ReturnsAsync("jwt.");
        var signer = new MeasuredJsonWebTokenSigner(inner.Object, _instruments);

        Assert.Equal("jwt.", await signer.SignAsync(new JsonWebToken(), null, TestContext.Current.CancellationToken));

        Assert.Empty(_measured.Of(OidcMetrics.TokenSigningDuration));
    }

    private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
}
