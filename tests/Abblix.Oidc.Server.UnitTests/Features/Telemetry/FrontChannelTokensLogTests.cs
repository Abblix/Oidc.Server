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
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using AuthorizationRequest = Abblix.Oidc.Server.Model.AuthorizationRequest;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// The tokens the authorization endpoint hands out through the front channel are recorded at Information from the
/// response the endpoint answers with, once it is encoded, under the implicit grant: a response carrying only a code
/// records nothing, and nor does a response the encoder turned into an error, as one whose response JWT could not be
/// built.
/// </summary>
public sealed class FrontChannelTokensLogTests : IDisposable
{
    private const string ClientId = "front-channel-client";
    private const string Subject = "the-raw-subject";
    private const string Audience = "https://api.example.com";
    private const string AccessTokenValue = "access-token-value";
    private const string IdTokenValue = "id-token-value";

    private readonly ServiceProvider _services = new ServiceCollection().AddMetrics().BuildServiceProvider();
    private readonly RecordingLoggerFactory _logs = new();

    public void Dispose() => _services.Dispose();

    private static readonly AuthorizationRequest Request = new() { ClientId = ClientId };

    private async Task Answer(AuthorizationResponse response)
    {
        var inner = new Mock<IAuthorizationHandler>();
        inner.Setup(h => h.HandleAsync(It.IsAny<TenantDefinition>(), Request)).ReturnsAsync(response);
        var observed = new ObservedAuthorizationHandler(
            inner.Object,
            _logs,
            TestFingerprints.Instance,
            new OidcInstruments(_logs, _services.GetRequiredService<System.Diagnostics.Metrics.IMeterFactory>()));

        await observed.HandleAsync(SingleIssuer.Tenant, Request);
    }

    private static SuccessfullyAuthenticated Authenticated(bool accessToken, bool idToken) => new(
        Request, ResponseModes.Fragment, "session", [])
    {
        SessionPersistence = SessionPersistence.BrowserSession,
        Code = "a-code",
        AccessToken = accessToken
            ? new EncodedJsonWebToken(new JsonWebToken { Payload = { Audiences = [Audience] } }, AccessTokenValue)
            : null,
        IdToken = idToken ? new EncodedJsonWebToken(new JsonWebToken(), IdTokenValue) : null,
        GrantedScopes = [Scopes.OpenId, "api.read"],
        Subject = Subject,
    };

    private LogRecord[] Recorded => _logs.Entries
        .Where(entry => entry.EventId.Id == LogEvents.TokenIssuance.IssuedTokensLog.FrontChannelTokensIssued)
        .ToArray();

    [Fact]
    public async Task TokensDelivered_AreRecordedWithTheClientTheGrantedScopeAndTheSubjectsFingerprint()
    {
        await Answer(Authenticated(accessToken: true, idToken: true));

        var record = Assert.Single(Recorded);
        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(SingleIssuer.Tenant.Id, record.Value("TenantId"));
        Assert.Equal(ClientId, record.Value("ClientId")?.ToString());
        Assert.Equal(GrantTypes.Implicit, record.Value("GrantType"));
        Assert.Equal(
            new[] { TelemetryTokenTypes.AccessToken, TelemetryTokenTypes.IdToken },
            Assert.IsType<string[]>(record.Value("Tokens")));
        Assert.Equal(
            [Scopes.OpenId, "api.read"],
            Assert.IsType<Sanitized[]>(record.Value("Scope")).Select(value => value.ToString()));
        Assert.Equal([Audience], Assert.IsType<Sanitized[]>(record.Value("Audiences")).Select(value => value.ToString()));
        var subject = Assert.IsType<Fingerprint>(record.Value("Subject"));
        Assert.Equal(TestFingerprints.Instance.Of(Subject).ToString(), subject.ToString());

        foreach (var leaked in new[] { Subject, AccessTokenValue, IdTokenValue })
        {
            Assert.DoesNotContain(leaked, record.Message);
            Assert.DoesNotContain(record.State!, pair => pair.Value?.ToString()?.Contains(leaked) == true);
        }
    }

    [Fact]
    public async Task AnIdTokenAlone_IsRecordedForNoAudience()
    {
        await Answer(Authenticated(accessToken: false, idToken: true));

        var record = Assert.Single(Recorded);
        Assert.Equal(new[] { TelemetryTokenTypes.IdToken }, Assert.IsType<string[]>(record.Value("Tokens")));
        Assert.Empty(Assert.IsType<Sanitized[]>(record.Value("Audiences")));
    }

    [Fact]
    public async Task ACodeAlone_IsNotRecordedAsATokenHandedOut()
    {
        await Answer(Authenticated(accessToken: false, idToken: false));

        Assert.Empty(Recorded);
    }

    /// <summary>
    /// The encoder answers a response whose response JWT cannot be built with unauthorized_client, so the tokens the
    /// processor minted never reach the client and are not recorded as handed out.
    /// </summary>
    [Fact]
    public async Task AResponseTheEncoderTurnedIntoAnError_IsNotRecorded()
    {
        await Answer(new AuthorizationError(
            Request, ErrorCodes.UnauthorizedClient, "no key", ResponseModes.FragmentJwt, new Uri("https://client.example.com/cb")));

        Assert.Empty(Recorded);
    }
}
