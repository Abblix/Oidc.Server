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
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.BackChannelAuthentication;

/// <remarks>
/// A pending request stays in the store past its expiry, so a poll arriving late is answered expired_token. Its
/// presence therefore no longer says it may be answered: one whose expiry has come is refused as one that is gone,
/// and nothing is written, so no expired request becomes one a poll could redeem.
/// </remarks>
public partial class AuthenticationCompletionHandlerTests
{
    [Fact]
    public async Task CompleteAuthenticationAsync_WhenTheStoredRequestHasExpired_RefusesAndWritesNothing()
    {
        var expired = PendingRecordExpiringAt(ApprovedAt);
        _storage.Setup(s => s.TryGetAsync(TestTenant.Matched, AuthReqId)).ReturnsAsync(expired);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => CreatePollModeHandler().CompleteAuthenticationAsync(
                SingleIssuer.Tenant, AuthReqId, expired, PollClient(), _expiresIn));

        Assert.Equal(BackChannelAuthenticationStatus.Pending, expired.Status);
    }

    [Fact]
    public async Task DenyAuthenticationAsync_WhenTheStoredRequestHasExpired_RefusesAndWritesNothing()
    {
        var expired = PendingRecordExpiringAt(ApprovedAt);
        _storage.Setup(s => s.TryGetAsync(TestTenant.Matched, AuthReqId)).ReturnsAsync(expired);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => CreatePollModeHandler().DenyAuthenticationAsync(SingleIssuer.Tenant, AuthReqId, _expiresIn));

        Assert.Equal(BackChannelAuthenticationStatus.Pending, expired.Status);
    }

    private static BackChannelAuthenticationRequest PendingRecordExpiringAt(DateTimeOffset expiresAt)
        => new(
            new AuthorizedGrant(
                new AuthSession(UserId, "stored_session", DateTimeOffset.UnixEpoch, "test"),
                new AuthorizationContext(ClientId, [Scopes.OpenId], null)),
            expiresAt)
        {
            Status = BackChannelAuthenticationStatus.Pending,
        };
}
