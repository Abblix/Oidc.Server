// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Revocation;

/// <summary>
/// Unit tests for <see cref="TokenStatusValidatorDecorator"/> covering refresh-token family revocation
/// per the OAuth 2.0 Security BCP (RFC 9700 Section 4.14.2) rotation model. The decorator turns a replay of a
/// superseded refresh token into a whole-family revocation and enforces the family kill switch on every
/// subsequent use, so a compromised grant is shut down rather than leaving the attacker's active token working.
/// </summary>
public class TokenStatusValidatorDecoratorTests
{
    private const string ActiveJwtId = "rt_jti_active";
    private const string GrantId = "grant_001";
    private const string Subject = "user_42";
    private const string SessionId = "session_7";
    private static readonly DateTimeOffset Expiry = new(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset IssuedAt = new(2024, 1, 15, 11, 0, 0, TimeSpan.Zero);

    private readonly Mock<ITokenRegistry> _registry = new(MockBehavior.Strict);
    private readonly Mock<IRevocationCutoffRegistry> _cutoffs = new(MockBehavior.Strict);
    private readonly Mock<IJsonWebTokenValidator> _inner = new(MockBehavior.Strict);
    private readonly TokenStatusValidatorDecorator _decorator;

    public TokenStatusValidatorDecoratorTests()
    {
        _decorator = new TokenStatusValidatorDecorator(_registry.Object, _cutoffs.Object, _inner.Object);

        // No cutoff recorded is the ordinary case, and every test not about cutoffs relies on it.
        _cutoffs
            .Setup(c => c.GetCutoffAsync(
                It.IsAny<RevocationScope>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((DateTimeOffset?)null);
    }

    /// <summary>
    /// Replay of a superseded (already-rotated) refresh token: the decorator cannot tell an attacker from a
    /// lagging client, so it revokes the whole family and reports the token as already used. This is the
    /// breach signal of RFC 9700 Section 4.14.2 - the point at which the active token in the lineage is doomed.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ReusedRefreshToken_RevokesFamilyAndReportsAlreadyUsed()
    {
        SetupInnerReturns(RefreshToken(GrantId));
        _registry.Setup(r => r.GetStatusAsync(GrantId)).ReturnsAsync(JsonWebTokenStatus.Unknown);
        _registry.Setup(r => r.GetStatusAsync(ActiveJwtId)).ReturnsAsync(JsonWebTokenStatus.Used);
        _registry
            .Setup(r => r.SetStatusAsync(GrantId, JsonWebTokenStatus.Revoked, Expiry))
            .Returns(Task.CompletedTask);

        var result = await _decorator.ValidateAsync("opaque.rt.jwt", new ValidationParameters());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.TokenAlreadyUsed, error.Error);
        _registry.Verify(r => r.SetStatusAsync(GrantId, JsonWebTokenStatus.Revoked, Expiry), Times.Once);
    }

    /// <summary>
    /// A structurally valid, not-yet-used refresh token whose family has already been revoked is rejected.
    /// This is the kill switch that outlives any single token: once a replay elsewhere in the lineage revoked
    /// the family, the currently active token dies on its next use, even though its own <c>jti</c> is still
    /// Unknown. The per-token status is never consulted - the family check short-circuits first.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ActiveTokenOfRevokedFamily_IsRejected()
    {
        SetupInnerReturns(RefreshToken(GrantId));
        _registry.Setup(r => r.GetStatusAsync(GrantId)).ReturnsAsync(JsonWebTokenStatus.Revoked);

        var result = await _decorator.ValidateAsync("opaque.rt.jwt", new ValidationParameters());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.TokenRevoked, error.Error);
        _registry.Verify(r => r.GetStatusAsync(ActiveJwtId), Times.Never);
    }

    /// <summary>
    /// A fresh refresh token of a live family passes through unchanged: neither the family nor the token has a
    /// non-neutral status, so the decorator returns the inner validator's success without any registry write.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_LiveRefreshToken_PassesThrough()
    {
        var token = RefreshToken(GrantId);
        SetupInnerReturns(token);
        _registry.Setup(r => r.GetStatusAsync(GrantId)).ReturnsAsync(JsonWebTokenStatus.Unknown);
        _registry.Setup(r => r.GetStatusAsync(ActiveJwtId)).ReturnsAsync(JsonWebTokenStatus.Unknown);

        var result = await _decorator.ValidateAsync("opaque.rt.jwt", new ValidationParameters());

        Assert.True(result.TryGetSuccess(out var validated));
        Assert.Same(token, validated);
    }

    /// <summary>
    /// Tokens without a family claim (access tokens, ID tokens - anything that is not a rotating refresh token)
    /// keep the pre-existing single-token behaviour: a used token is rejected, but no family cascade fires. This
    /// proves the family logic is inert for non-refresh tokens rather than reaching for a null family key.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_UsedTokenWithoutFamily_RejectsWithoutTouchingAnyFamily()
    {
        SetupInnerReturns(RefreshToken(grantId: null));
        _registry.Setup(r => r.GetStatusAsync(ActiveJwtId)).ReturnsAsync(JsonWebTokenStatus.Used);

        var result = await _decorator.ValidateAsync("opaque.at.jwt", new ValidationParameters());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.TokenAlreadyUsed, error.Error);
        _registry.Verify(
            r => r.SetStatusAsync(It.IsAny<string>(), It.IsAny<JsonWebTokenStatus>(), It.IsAny<DateTimeOffset>()),
            Times.Never);
    }

    /// <summary>
    /// A cutoff recorded against the subject rejects a token issued before it. This is what an account
    /// suspension or a "sign out everywhere" acts through: one write, and every token minted earlier - across
    /// every session of that user - stops being accepted.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenIssuedBeforeTheSubjectCutoff_IsRejected()
    {
        SetupInnerReturns(RefreshToken(GrantId));
        SetupCutoff(RevocationScope.Subject, Subject, IssuedAt.AddSeconds(1));

        var result = await _decorator.ValidateAsync("opaque.rt.jwt", new ValidationParameters());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.TokenRevoked, error.Error);
    }

    /// <summary>
    /// A token issued after the cutoff passes, which is the property that makes a cutoff usable at all: the
    /// user signs in again and their new tokens work, with nothing to clean up. A boolean flag could not do
    /// this - it would keep refusing every later session too.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenIssuedAfterTheSubjectCutoff_IsAccepted()
    {
        SetupInnerReturns(RefreshToken(GrantId));
        SetupCutoff(RevocationScope.Subject, Subject, IssuedAt.AddSeconds(-1));
        _registry.Setup(r => r.GetStatusAsync(GrantId)).ReturnsAsync(JsonWebTokenStatus.Unknown);
        _registry.Setup(r => r.GetStatusAsync(ActiveJwtId)).ReturnsAsync(JsonWebTokenStatus.Unknown);

        var result = await _decorator.ValidateAsync("opaque.rt.jwt", new ValidationParameters());

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// A session cutoff reaches a token of that session, leaving the same user's other sessions alone. Signing
    /// out of one device must not sign the user out of the rest.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenOfACutOffSession_IsRejected()
    {
        SetupInnerReturns(RefreshToken(GrantId));
        SetupCutoff(RevocationScope.Session, SessionId, IssuedAt.AddSeconds(1));

        var result = await _decorator.ValidateAsync("opaque.rt.jwt", new ValidationParameters());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.TokenRevoked, error.Error);
    }

    /// <summary>
    /// A cutoff reaches a token carrying no identifier of its own. The per-token arms are all guarded by
    /// <c>jti</c>, which RFC 7519 Section 4.1.7 makes OPTIONAL, so a cutoff checked alongside them would let
    /// exactly the tokens with no <c>jti</c> through - and nothing about a suspended account says its tokens
    /// happen to be identified.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenWithoutAnIdentifier_IsStillReachedByACutoff()
    {
        SetupInnerReturns(new JsonWebToken
        {
            Payload =
            {
                ExpiresAt = Expiry,
                Subject = Subject,
                IssuedAt = IssuedAt,
            }
        });
        SetupCutoff(RevocationScope.Subject, Subject, IssuedAt.AddSeconds(1));

        var result = await _decorator.ValidateAsync("opaque.at.jwt", new ValidationParameters());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.TokenRevoked, error.Error);
    }

    /// <summary>
    /// A token carrying no issue time is left alone: with nothing to measure against the cutoff, refusing it
    /// would revoke tokens on the strength of a claim that was never there.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_TokenWithoutAnIssueTime_IsNotReachedByACutoff()
    {
        SetupInnerReturns(new JsonWebToken
        {
            Payload =
            {
                JwtId = ActiveJwtId,
                ExpiresAt = Expiry,
                Subject = Subject,
            }
        });
        SetupCutoff(RevocationScope.Subject, Subject, Expiry);
        _registry.Setup(r => r.GetStatusAsync(ActiveJwtId)).ReturnsAsync(JsonWebTokenStatus.Unknown);

        var result = await _decorator.ValidateAsync("opaque.at.jwt", new ValidationParameters());

        Assert.True(result.TryGetSuccess(out _));
    }

    private void SetupCutoff(RevocationScope scope, string principal, DateTimeOffset cutoff)
        => _cutoffs
            .Setup(c => c.GetCutoffAsync(scope, principal, It.IsAny<CancellationToken>()))
            .ReturnsAsync(cutoff);

    private void SetupInnerReturns(JsonWebToken token)
    {
        Result<JsonWebToken, JwtValidationError> success = token;
        _inner
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .ReturnsAsync(success);
    }

    private static JsonWebToken RefreshToken(string? grantId) => new()
    {
        Payload =
        {
            JwtId = ActiveJwtId,
            ExpiresAt = Expiry,
            GrantId = grantId,
            Subject = Subject,
            SessionId = SessionId,
            IssuedAt = IssuedAt,
        }
    };
}
