// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Revocation;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Revocation;

/// <summary>
/// A refresh token's grant is revoked as a whole, from the revocation endpoint and from a replayed refresh token
/// alike, and stays revoked as long as any token of the grant could still be valid.
/// </summary>
/// <remarks>
/// Driven through the real refresh token service, revocation processor and status decorator over a registry that
/// forgets an entry at its expiry, as the storage behind the real registry does.
/// </remarks>
public class GrantRevocationTests
{
    private const string GrantId = "grant_1";
    private const string ClientId = "client_1";
    private static readonly DateTimeOffset Start = new(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// A registry that forgets an entry once its expiry passes, keeping each tenant's entries apart.
    /// </summary>
    private sealed class ExpiringRegistry(TimeProvider clock) : ITokenRegistry
    {
        private readonly Dictionary<string, (JsonWebTokenStatus Status, DateTimeOffset ExpiresAt)> _entries = new();

        public Task<JsonWebTokenStatus> GetStatusAsync(TenantDefinition tenant, string jwtId)
            => Task.FromResult(
                _entries.TryGetValue(TenantKey.Of(tenant, jwtId), out var entry) && clock.GetUtcNow() < entry.ExpiresAt
                    ? entry.Status
                    : JsonWebTokenStatus.Unknown);

        public Task SetStatusAsync(
            TenantDefinition tenant,
            string jwtId,
            JsonWebTokenStatus status,
            DateTimeOffset expiresAt)
        {
            _entries[TenantKey.Of(tenant, jwtId)] = (status, expiresAt);
            return Task.CompletedTask;
        }

        public async Task<bool> TrySetStatusAsync(
            TenantDefinition tenant,
            string jwtId,
            JsonWebTokenStatus status,
            DateTimeOffset expiresAt)
        {
            if (await GetStatusAsync(tenant, jwtId) != JsonWebTokenStatus.Unknown)
                return false;

            await SetStatusAsync(tenant, jwtId, status, expiresAt);
            return true;
        }

        /// <summary>When the entry the test's tenant keeps under <paramref name="jwtId"/> expires.</summary>
        public DateTimeOffset ExpiryOf(string jwtId) => _entries[TenantKey.Of(SingleIssuer.Tenant, jwtId)].ExpiresAt;
    }

    private readonly FakeTimeProvider _clock = new(Start);
    private readonly ExpiringRegistry _registry;
    private readonly RefreshTokenService _service;
    private readonly RevocationRequestProcessor _processor;
    private readonly TokenStatusValidatorDecorator _decorator;
    private readonly Dictionary<string, JsonWebToken> _issued = new(StringComparer.Ordinal);
    private int _next;

    public GrantRevocationTests()
    {
        _registry = new ExpiringRegistry(_clock);
        var ids = new Mock<ITokenIdGenerator>();
        ids.Setup(generator => generator.GenerateTokenId()).Returns(() => "jti_" + ++_next);
        var formatter = new Mock<IAuthServiceJwtFormatter>();
        formatter
            .Setup(f => f.FormatAsync(TestTenant.Matched, It.IsAny<JsonWebToken>(), It.IsAny<ServiceJwtEncryption>()))
            .ReturnsAsync((TenantDefinition _, JsonWebToken jwt, ServiceJwtEncryption _) =>
            {
                _issued[jwt.Payload.JwtId!] = jwt;
                return jwt.Payload.JwtId!;
            });

        var clients = new Mock<IClientInfoProvider>();
        clients.Setup(provider => provider.TryFindClientAsync(TestTenant.Matched, ClientId)).ReturnsAsync(() => _knownClient ? _client : null);
        var grants = new GrantRevocation(_registry, clients.Object);

        var options = Options.Create(new OidcOptions());
        _service = new RefreshTokenService(
            _clock, ids.Object, formatter.Object, _registry, grants, new FixedSubjectTypeConverter(new SubjectTypeConverter()),
            options, SingleIssuer.LicensedCatalog);
        _processor = new RevocationRequestProcessor(_registry, grants, _clock);

        var inner = new Mock<IJsonWebTokenValidator>();
        inner
            .Setup(validator => validator.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .ReturnsAsync((string jwt, ValidationParameters _) => (Result<JsonWebToken, JwtValidationError>)_issued[jwt]);
        var cutoff = new Mock<IRevocationCutoffChecker>();
        cutoff.Setup(checker => checker.CheckAsync(TestTenant.Matched, It.IsAny<JsonWebTokenPayload>())).ReturnsAsync((JwtValidationError?)null);
        _decorator = new TokenStatusValidatorDecorator(_registry, cutoff.Object, grants, inner.Object, tenantAccessor: SingleIssuer.Accessor);
    }

    private ClientInfo _client = ClientWith(RefreshTokenReusePolicy.Rotate);
    private bool _knownClient = true;

    private static ClientInfo ClientWith(RefreshTokenReusePolicy reusePolicy) => new(ClientId)
    {
        AccessTokenExpiresIn = TimeSpan.FromHours(1),
        RefreshToken = new RefreshTokenOptions
        {
            AbsoluteExpiresIn = TimeSpan.FromHours(8),
            SlidingExpiresIn = TimeSpan.FromHours(1),
            ReusePolicy = reusePolicy,
        },
    };

    private async Task<JsonWebToken> RefreshAsync(JsonWebToken? previous)
    {
        var session = new AuthSession("user_1", "session_1", Start, "test");
        var context = new AuthorizationContext(ClientId, [Scopes.OpenId, Scopes.OfflineAccess], null);

        var encoded = await _service.CreateRefreshTokenAsync(SingleIssuer.Tenant, session, context, _client, previous, GrantId);

        // The token endpoint spends the presented token once the response is issued.
        if (previous != null)
            Assert.True(await _service.TrySpendAsync(SingleIssuer.Tenant, previous, _client));

        return encoded!.Token;
    }

    private Task RevokeAsync(JsonWebToken token) => _processor.ProcessAsync(
        SingleIssuer.Tenant,
        new ValidRevocationRequest(new RevocationRequest { Token = token.Payload.JwtId! }, token));

    private async Task<bool> AcceptedAsync(JsonWebToken token)
        => (await _decorator.ValidateAsync(token.Payload.JwtId!, new ValidationParameters { TokenTypes = TokenTypePolicy.CheckedByCaller })).TryGetSuccess(out _);

    private JsonWebToken AccessTokenOfTheGrant()
    {
        var token = new JsonWebToken
        {
            Header = { Type = JsonWebTokenTypes.AccessToken },
            Payload =
            {
                JwtId = "access_" + ++_next,
                IssuedAt = _clock.GetUtcNow(),
                ExpiresAt = _clock.GetUtcNow() + TimeSpan.FromHours(1),
                ClientId = ClientId,
                GrantId = GrantId,
            },
        };
        _issued[token.Payload.JwtId!] = token;
        return token;
    }

    /// <summary>
    /// With reuse, each refresh issues a sibling, and revoking the newest one refuses every sibling and what they
    /// would mint.
    /// </summary>
    [Fact]
    public async Task RevokingOneRefreshTokenOfAReusedGrant_RefusesItsSiblings()
    {
        _client = ClientWith(RefreshTokenReusePolicy.Reuse);
        var first = await RefreshAsync(null);
        _clock.Advance(TimeSpan.FromMinutes(10));
        var second = await RefreshAsync(first);
        Assert.True(await AcceptedAsync(first));

        await RevokeAsync(second);

        Assert.False(await AcceptedAsync(second));
        Assert.False(await AcceptedAsync(first));
    }

    /// <summary>
    /// Revoking a refresh token refuses the access tokens of its grant (RFC 7009 section 2.1).
    /// </summary>
    [Fact]
    public async Task RevokingARefreshToken_RefusesTheAccessTokensOfItsGrant()
    {
        var refreshToken = await RefreshAsync(null);
        var accessToken = AccessTokenOfTheGrant();
        Assert.True(await AcceptedAsync(accessToken));

        await RevokeAsync(refreshToken);

        Assert.False(await AcceptedAsync(accessToken));
    }

    /// <summary>
    /// Revoking an access token leaves its grant: the client can still refresh.
    /// </summary>
    [Fact]
    public async Task RevokingAnAccessToken_LeavesItsGrant()
    {
        var refreshToken = await RefreshAsync(null);
        var accessToken = AccessTokenOfTheGrant();

        await RevokeAsync(accessToken);

        Assert.False(await AcceptedAsync(accessToken));
        Assert.True(await AcceptedAsync(refreshToken));
    }

    /// <summary>
    /// A grant revoked by replaying a rotated refresh token stays revoked past the replayed token's expiry, while
    /// the active token, issued later, could still be valid.
    /// </summary>
    [Fact]
    public async Task AGrantRevokedByAReplay_StaysRevoked_PastTheReplayedTokensExpiry()
    {
        var first = await RefreshAsync(null);
        _clock.Advance(TimeSpan.FromMinutes(30));
        var active = await RefreshAsync(first);
        _clock.Advance(TimeSpan.FromMinutes(10));
        Assert.False(await AcceptedAsync(first));

        _clock.Advance(TimeSpan.FromMinutes(25));
        Assert.True(_clock.GetUtcNow() > first.Payload.ExpiresAt);
        Assert.True(_clock.GetUtcNow() < active.Payload.ExpiresAt);

        Assert.False(await AcceptedAsync(active));
    }

    /// <summary>
    /// An access token issued from the last refresh token of a grant, close to the grant's absolute expiry, outlives
    /// every refresh token of the grant, and is still refused once their last moment has passed. The client keeps
    /// its grant alive by refreshing before each sliding expiry, as a real one does.
    /// </summary>
    [Fact]
    public async Task AnAccessTokenIssuedNearTheGrantsEnd_IsRefused_AfterItsRefreshTokensExpire()
    {
        _client = ClientWith(RefreshTokenReusePolicy.Reuse);
        var refreshToken = await RefreshAsync(null);
        while (_clock.GetUtcNow() < Start + TimeSpan.FromHours(7.5))
        {
            _clock.Advance(TimeSpan.FromMinutes(50));
            refreshToken = await RefreshAsync(refreshToken);
        }

        Assert.True(await AcceptedAsync(refreshToken));
        var accessToken = AccessTokenOfTheGrant();
        _clock.Advance(TimeSpan.FromMinutes(15));

        await RevokeAsync(refreshToken);
        _clock.Advance(TimeSpan.FromMinutes(20));
        Assert.True(_clock.GetUtcNow() > Start + TimeSpan.FromHours(8));
        Assert.True(_clock.GetUtcNow() < accessToken.Payload.ExpiresAt);

        Assert.False(await AcceptedAsync(accessToken));
    }

    /// <summary>
    /// Without the client or the grant's first issuance there is no ceiling to compute, and the grant stays revoked
    /// until the presented token's own expiry.
    /// </summary>
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task WithoutTheClientOrTheFirstIssuance_TheGrantIsRevokedUntilThePresentedTokensExpiry(
        bool knownClient,
        bool withIssueTime)
    {
        var refreshToken = await RefreshAsync(null);
        if (!withIssueTime)
            refreshToken.Payload.IssuedAt = null;

        _knownClient = knownClient;

        await RevokeAsync(refreshToken);

        Assert.Equal(refreshToken.Payload.ExpiresAt, _registry.ExpiryOf(GrantId));
    }

    /// <summary>
    /// A grant revoked at the revocation endpoint stays revoked past the presented token's expiry, while a sibling
    /// issued later could still be valid.
    /// </summary>
    [Fact]
    public async Task AGrantRevokedAtTheEndpoint_StaysRevoked_PastThePresentedTokensExpiry()
    {
        _client = ClientWith(RefreshTokenReusePolicy.Reuse);
        var first = await RefreshAsync(null);
        _clock.Advance(TimeSpan.FromMinutes(50));
        var later = await RefreshAsync(first);

        await RevokeAsync(first);
        _clock.Advance(TimeSpan.FromMinutes(20));
        Assert.True(_clock.GetUtcNow() > first.Payload.ExpiresAt);

        Assert.False(await AcceptedAsync(later));
    }
}
