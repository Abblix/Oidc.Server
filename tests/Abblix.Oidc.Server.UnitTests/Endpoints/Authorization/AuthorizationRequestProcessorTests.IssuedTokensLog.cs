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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Authorization;

public partial class AuthorizationRequestProcessorTests
{
    private const string Audience = "https://api.example.com";

    // The tokens an authorization response hands out through the front channel are recorded once the response is
    // final, under the implicit grant; a response carrying only a code, and one a builder refused, record nothing.
    private LogRecord[] FrontChannelRecords
        => _logs.Entries
            .Where(entry => entry.EventId.Id == LogEvents.TokenIssuance.IssuedTokensLog.FrontChannelTokensIssued)
            .ToArray();

    private void ServeSessionAndConsents(ValidAuthorizationRequest request)
    {
        var session = CreateAuthSession();
        _authSessionService
            .Setup(s => s.GetAvailableAuthSessions())
            .Returns(new[] { session }.ToAsyncEnumerable());
        _consentsProvider
            .Setup(p => p.GetUserConsentsAsync(TestTenant.Matched, request, session))
            .ReturnsAsync(CreateConsents());
    }

    [Fact]
    public async Task TokensThroughTheFrontChannel_AreRecordedWithTheClientAndTheSubjectsFingerprint()
    {
        var request = CreateRequest(responseType: [ResponseTypes.Token, ResponseTypes.IdToken]);
        ServeSessionAndConsents(request);
        var accessToken = new JsonWebToken { Payload = { Audiences = [Audience] } };
        _accessTokenService
            .Setup(s => s.CreateAccessTokenAsync(
                TestTenant.Matched, It.IsAny<AuthSession>(), It.IsAny<AuthorizationContext>(),
                request.ClientInfo, null, It.IsAny<DateTimeOffset?>()))
            .ReturnsAsync(new EncodedJsonWebToken(accessToken, "access_token_jwt"));
        _identityTokenService
            .Setup(s => s.CreateIdentityTokenAsync(TestTenant.Matched, It.IsAny<IdentityTokenRequest>()))
            .ReturnsAsync(new EncodedJsonWebToken(new JsonWebToken(), "id_token_jwt"));

        Assert.IsType<SuccessfullyAuthenticated>(await _processor.ProcessAsync(SingleIssuer.Tenant, request));

        var record = Assert.Single(FrontChannelRecords);
        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(SingleIssuer.Tenant.Id, record.Value("TenantId"));
        Assert.Equal(request.ClientInfo.ClientId, record.Value("ClientId")?.ToString());
        Assert.Equal(GrantTypes.Implicit, record.Value("GrantType"));
        Assert.Equal(
            new[] { TelemetryTokenTypes.AccessToken, TelemetryTokenTypes.IdToken },
            Assert.IsType<string[]>(record.Value("Tokens")));
        var subject = Assert.IsType<Fingerprint>(record.Value("Subject"));
        Assert.Equal(TestFingerprints.Instance.Of(CreateAuthSession().Subject).ToString(), subject.ToString());
        Assert.Equal(
            [Audience],
            Assert.IsType<Sanitized[]>(record.Value("Audiences")).Select(value => value.ToString()));

        Assert.DoesNotContain("access_token_jwt", record.Message);
        Assert.DoesNotContain("id_token_jwt", record.Message);
        Assert.DoesNotContain(CreateAuthSession().Subject, record.Message);
    }

    [Fact]
    public async Task ACodeAlone_IsNotRecordedAsATokenHandedOut()
    {
        var request = CreateRequest(responseType: [ResponseTypes.Code]);
        ServeSessionAndConsents(request);
        _authorizationCodeService
            .Setup(s => s.GenerateAuthorizationCodeAsync(
                TestTenant.Matched, It.IsAny<AuthorizedGrant>(), request.ClientInfo.AuthorizationCodeExpiresIn))
            .ReturnsAsync("auth_code_123");

        Assert.IsType<SuccessfullyAuthenticated>(await _processor.ProcessAsync(SingleIssuer.Tenant, request));

        Assert.Empty(FrontChannelRecords);
    }

    [Fact]
    public async Task AResponseABuilderRefused_IsNotRecorded()
    {
        var request = CreateRequest(responseType: [ResponseTypes.IdToken]);
        ServeSessionAndConsents(request);
        _identityTokenService
            .Setup(s => s.CreateIdentityTokenAsync(TestTenant.Matched, It.IsAny<IdentityTokenRequest>()))
            .ReturnsAsync(new OidcError(ErrorCodes.InvalidClient, "no usable key"));

        Assert.IsType<AuthorizationError>(await _processor.ProcessAsync(SingleIssuer.Tenant, request));

        Assert.Empty(FrontChannelRecords);
    }
}
