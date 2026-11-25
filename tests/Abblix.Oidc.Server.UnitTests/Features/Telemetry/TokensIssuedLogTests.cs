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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// Each token request answered with tokens, whatever its grant, is recorded at Information under one event id: the
/// tenant, the client, the subject by its fingerprint, the grant type and family, and the scope and audiences of the
/// access token, and never a token value or the raw subject. A request refused records nothing.
/// </summary>
public sealed class TokensIssuedLogTests : IDisposable
{
    private const string ClientId = "client-handed-tokens";
    private const string Subject = "the-raw-subject";
    private const string GrantId = "family-1";
    private const string Audience = "https://api.example.com";
    private const string AccessTokenValue = "access-token-value";
    private const string RefreshTokenValue = "refresh-token-value";
    private const string IdTokenValue = "id-token-value";

    private readonly ServiceProvider _services = new ServiceCollection().AddMetrics().BuildServiceProvider();
    private readonly RecordingLoggerFactory _logs = new();

    public void Dispose() => _services.Dispose();

    private MeasuredTokenRequestProcessor Processor(Result<TokenIssued, OidcError> outcome)
    {
        var inner = new Mock<ITokenRequestProcessor>();
        inner
            .Setup(processor => processor.ProcessAsync(It.IsAny<TenantDefinition>(), It.IsAny<ValidTokenRequest>()))
            .ReturnsAsync(outcome);
        return new MeasuredTokenRequestProcessor(
            new Logger<MeasuredTokenRequestProcessor>(_logs),
            TestFingerprints.Instance,
            inner.Object,
            new OidcInstruments(_logs, _services.GetRequiredService<System.Diagnostics.Metrics.IMeterFactory>()),
            Mock.Of<IAuthorizationGrantHandler>());
    }

    private static ValidTokenRequest Request(string grantType) => new(
        new TokenRequest { GrantType = grantType },
        new AuthorizedGrant(
            new AuthSession(Subject, "session-1", DateTimeOffset.UnixEpoch, "idp"),
            new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
        new ClientInfo(ClientId),
        [],
        []);

    private static TokenIssued Issued(bool derived)
    {
        var accessToken = new JsonWebToken
        {
            Payload = { Scope = [Scopes.OpenId, "api.read"], Audiences = [Audience], GrantId = GrantId },
        };
        return new TokenIssued(
            new EncodedJsonWebToken(accessToken, AccessTokenValue),
            TokenTypes.Bearer,
            TimeSpan.FromMinutes(5),
            new Uri(TokenExchangeTokenTypes.AccessToken))
        {
            RefreshToken = derived ? new EncodedJsonWebToken(new JsonWebToken(), RefreshTokenValue) : null,
            IdToken = derived ? new EncodedJsonWebToken(new JsonWebToken(), IdTokenValue) : null,
        };
    }

    private LogRecord[] Recorded => _logs.Entries
        .Where(entry => entry.EventId.Id == LogEvents.TokenIssuance.IssuedTokensLog.TokensIssued)
        .ToArray();

    [Theory]
    [InlineData(GrantTypes.AuthorizationCode)]
    [InlineData(GrantTypes.RefreshToken)]
    [InlineData(GrantTypes.ClientCredentials)]
    [InlineData(GrantTypes.Password)]
    [InlineData(GrantTypes.Ciba)]
    [InlineData(GrantTypes.JwtBearer)]
    [InlineData(GrantTypes.DeviceAuthorization)]
    [InlineData(GrantTypes.TokenExchange)]
    public async Task TokensIssuedUnderAnyGrant_AreRecordedWithWhoGotWhat(string grantType)
    {
        await Processor(Issued(derived: true)).ProcessAsync(SingleIssuer.Tenant, Request(grantType));

        var record = Assert.Single(Recorded);
        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(SingleIssuer.Tenant.Id, record.Value("TenantId"));
        Assert.Equal(ClientId, record.Value("ClientId")?.ToString());
        Assert.Equal(grantType, record.Value("GrantType")?.ToString());
        Assert.Equal(GrantId, record.Value("GrantId")?.ToString());
        Assert.Equal(
            new[] { TelemetryTokenTypes.AccessToken, TelemetryTokenTypes.RefreshToken, TelemetryTokenTypes.IdToken },
            Assert.IsType<string[]>(record.Value("Tokens")));
        Assert.Equal(
            [Scopes.OpenId, "api.read"],
            Assert.IsType<Sanitized[]>(record.Value("Scope")).Select(value => value.ToString()));
        Assert.Equal([Audience], Assert.IsType<Sanitized[]>(record.Value("Audiences")).Select(value => value.ToString()));

        var subject = Assert.IsType<Fingerprint>(record.Value("Subject"));
        Assert.Equal(TestFingerprints.Instance.Of(Subject).ToString(), subject.ToString());

        foreach (var leaked in new[] { Subject, AccessTokenValue, RefreshTokenValue, IdTokenValue })
        {
            Assert.DoesNotContain(leaked, record.Message);
            Assert.DoesNotContain(record.State!, pair => pair.Value?.ToString()?.Contains(leaked) == true);
        }
    }

    [Fact]
    public async Task AnAccessTokenAlone_IsRecordedAsTheOnlyTokenWithNoFamily()
    {
        var issued = Issued(derived: false);
        issued.AccessToken.Token.Payload.GrantId = null;

        await Processor(issued).ProcessAsync(SingleIssuer.Tenant, Request(GrantTypes.ClientCredentials));

        var record = Assert.Single(Recorded);
        Assert.Equal(new[] { TelemetryTokenTypes.AccessToken }, Assert.IsType<string[]>(record.Value("Tokens")));
        Assert.Null(((Sanitized)record.Value("GrantId")!).Source);
    }

    [Fact]
    public async Task ARefusedRequest_RecordsNothing()
    {
        await Processor(new OidcError(ErrorCodes.InvalidGrant, "refused"))
            .ProcessAsync(SingleIssuer.Tenant, Request(GrantTypes.AuthorizationCode));

        Assert.Empty(Recorded);
    }
}
