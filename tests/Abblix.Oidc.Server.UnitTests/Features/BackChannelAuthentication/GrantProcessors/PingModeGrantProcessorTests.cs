// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Globalization;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.GrantProcessors;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication.GrantProcessors;

/// <summary>
/// Verifies that CIBA ping mode consumes the <c>auth_req_id</c> on token retrieval. CIBA Core 1.0
/// Section 10.1.1 says "Once redeemed for a successful token response, the auth_req_id value that
/// was used is no longer valid", and defines the token response identically for poll and ping. Ping therefore must remove the grant from storage
/// on first successful retrieval, exactly like poll, so a notified client cannot replay the same
/// <c>auth_req_id</c> to mint fresh tokens until expiry.
/// </summary>
public class PingModeGrantProcessorTests
{
    private const string AuthRequestId = "auth-req-id-123";

    private readonly Mock<IBackChannelRequestStorage> _storage;
    private readonly PingModeGrantProcessor _processor;
    private readonly BackChannelAuthenticationRequest _request;

    public PingModeGrantProcessorTests()
    {
        var fixedTime = DateTimeOffset.Parse("2026-01-01T00:00:00Z", CultureInfo.InvariantCulture);
        var session = new AuthSession("user-1", "session-1", fixedTime, "local");
        var context = new AuthorizationContext("client-1", [TestConstants.DefaultScope], null);
        _request = new BackChannelAuthenticationRequest(new AuthorizedGrant(session, context), fixedTime.AddMinutes(5));

        _storage = new Mock<IBackChannelRequestStorage>(MockBehavior.Strict);
        _processor = new PingModeGrantProcessor(_storage.Object);
    }

    [Fact]
    public async Task Process_ConsumesAuthReqIdFromStorage()
    {
        _storage.Setup(s => s.TryRemoveAsync(AuthRequestId)).ReturnsAsync(_request);

        var result = await _processor.ProcessAuthenticatedRequestAsync(AuthRequestId, _request);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal(_request.AuthorizedGrant, grant);
        _storage.Verify(s => s.TryRemoveAsync(AuthRequestId), Times.Once);
    }

    [Fact]
    public async Task Process_SecondRetrieval_ReturnsInvalidGrant()
    {
        // First retrieval consumes the entry; the second sees nothing in storage and must fail
        // rather than re-issue tokens for the same single-use auth_req_id.
        _storage.SetupSequence(s => s.TryRemoveAsync(AuthRequestId))
            .ReturnsAsync(_request)
            .ReturnsAsync((BackChannelAuthenticationRequest?)null);

        var first = await _processor.ProcessAuthenticatedRequestAsync(AuthRequestId, _request);
        var second = await _processor.ProcessAuthenticatedRequestAsync(AuthRequestId, _request);

        Assert.True(first.TryGetSuccess(out _));
        Assert.True(second.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidGrant, error.Error);
    }
}
