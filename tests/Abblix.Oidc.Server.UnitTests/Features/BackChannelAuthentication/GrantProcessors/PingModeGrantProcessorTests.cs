// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
/// Section 7.3 states the <c>auth_req_id</c> can be used only once; Section 10.1.1 defines the
/// token response identically for poll and ping. Ping therefore must remove the grant from storage
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
