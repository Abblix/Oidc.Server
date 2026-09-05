// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using System.Threading;
using System;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Revocation;

/// <summary>
/// Unit tests for <see cref="TokenStatusValidatorDecorator"/> covering the two revocations it enforces:
/// the refresh-token family per the OAuth 2.0 Security BCP (RFC 9700 Section 4.14.2) rotation model, and
/// the subject- and session-level cutoffs an administrator writes. The decorator turns a replay of a
/// superseded refresh token into a whole-family revocation and enforces the family kill switch on every
/// subsequent use, so a compromised grant is shut down rather than leaving the attacker's active token working.
/// </summary>
public class TokenStatusValidatorDecoratorTests
{
    private const string ActiveJwtId = "rt_jti_active";
    private const string GrantId = "grant_001";
    private const string Subject = "user_42";
    private const string SessionId = "session_7";
    private const string ClientId = "client_1";
    private const string SectorIdentifier = "https://sector.example.com/uris.json";

    // A cutoff names a principal in this server's namespace, so it applies only to tokens this server
    // issued. Every payload below therefore has to say who issued it.
    private static readonly string Issuer = TestConstants.DefaultIssuer.OriginalString;

    private static readonly ISubjectTypeConverter SubjectConverter =
        new SubjectTypeConverter(new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) });
    private static readonly DateTimeOffset Expiry = new(2024, 1, 15, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset IssuedAt = new(2024, 1, 15, 11, 0, 0, TimeSpan.Zero);

    private readonly Mock<ITokenRegistry> _registry = new(MockBehavior.Strict);
    private readonly Mock<IRevocationCutoffRegistry> _cutoffs = new(MockBehavior.Strict);
    private readonly Mock<IClientInfoProvider> _clients = new(MockBehavior.Strict);
    private readonly Mock<IIssuerProvider> _issuers = new(MockBehavior.Strict);
    private readonly Mock<IJsonWebTokenValidator> _inner = new(MockBehavior.Strict);
    private readonly TokenStatusValidatorDecorator _decorator;

    public TokenStatusValidatorDecoratorTests()
    {
        // The real converter, not a mock: what has to hold is that a pairwise pseudonym opens back into the
        // subject a host revoked, and a stub told to return the right answer proves nothing about that.
        _issuers.Setup(p => p.GetIssuer()).Returns(Issuer);

        _decorator = new TokenStatusValidatorDecorator(
            _registry.Object,
            CutoffChecker(TimeSpan.Zero),
            _inner.Object);

        // No cutoff recorded is the ordinary case, and every test not about cutoffs relies on it.
        _cutoffs
            .Setup(c => c.GetCutoffAsync(
                It.IsAny<RevocationScope>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((DateTimeOffset?)null);

        // A public client is what every test but the pairwise one carries, and for it the subject in the
        // token is already the subject a host would revoke.
        _clients
            .Setup(p => p.TryFindClientAsync(It.IsAny<string>()))
            .ReturnsAsync(new ClientInfo(ClientId) { SubjectType = SubjectTypes.Public });
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
        _cutoffs.Verify(
            c => c.GetCutoffAsync(RevocationScope.Subject, Subject, It.IsAny<CancellationToken>()), Times.Once);
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
                Issuer = Issuer,
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
                Issuer = Issuer,
                JwtId = ActiveJwtId,
                ExpiresAt = Expiry,
                Subject = Subject,
            }
        });
        SetupCutoff(RevocationScope.Subject, Subject, Expiry);
        _registry.Setup(r => r.GetStatusAsync(ActiveJwtId)).ReturnsAsync(JsonWebTokenStatus.Unknown);

        var result = await _decorator.ValidateAsync("opaque.at.jwt", new ValidationParameters());

        Assert.True(result.TryGetSuccess(out _));

        // Nothing was even asked: with no issue time there is nothing to measure, so the store is not
        // consulted at all. Without this the test passes over a decorator that ignores cutoffs entirely.
        _cutoffs.Verify(
            c => c.GetCutoffAsync(
                It.IsAny<RevocationScope>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    /// <summary>
    /// A pairwise client's token carries a per-sector pseudonym rather than the subject a host revoked, and
    /// the cutoff still reaches it. Without opening the pseudonym, a suspension refuses every public client's
    /// tokens and silently misses every pairwise one - the deployment most likely to need it.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_PairwiseTokenOfARevokedSubject_IsRejected()
    {
        var pairwiseClient = new ClientInfo(ClientId)
        {
            SubjectType = SubjectTypes.Pairwise,
            SectorIdentifier = SectorIdentifier,
        };
        _clients.Setup(p => p.TryFindClientAsync(ClientId)).ReturnsAsync(pairwiseClient);

        var pseudonym = SubjectConverter.Convert(Subject, pairwiseClient);
        Assert.NotEqual(Subject, pseudonym); // the fixture is only meaningful if the two actually differ

        SetupInnerReturns(new JsonWebToken
        {
            Payload =
            {
                Issuer = Issuer,
                JwtId = ActiveJwtId,
                ExpiresAt = Expiry,
                Subject = pseudonym,
                ClientId = ClientId,
                IssuedAt = IssuedAt,
            }
        });

        // The host revokes the subject it knows, which is the real one.
        SetupCutoff(RevocationScope.Subject, Subject, IssuedAt.AddSeconds(1));

        var result = await _decorator.ValidateAsync("opaque.at.jwt", new ValidationParameters());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.TokenRevoked, error.Error);
    }

    /// <summary>
    /// A caller that has switched lifetime validation off is not refused by a cutoff. The logout endpoint is
    /// the case: an <c>id_token_hint</c> names the session that just ended, so a session cutoff written by
    /// that very logout would refuse the hint on any second attempt - a browser refresh, a retrying relying
    /// party, or the second relying party of a multi-party logout.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_WhenTheCallerDoesNotValidateLifetime_ACutoffDoesNotRefuse()
    {
        SetupInnerReturns(RefreshToken(GrantId));
        SetupCutoff(RevocationScope.Session, SessionId, IssuedAt.AddSeconds(1));
        _registry.Setup(r => r.GetStatusAsync(GrantId)).ReturnsAsync(JsonWebTokenStatus.Unknown);
        _registry.Setup(r => r.GetStatusAsync(ActiveJwtId)).ReturnsAsync(JsonWebTokenStatus.Unknown);

        var result = await _decorator.ValidateAsync(
            "opaque.id.jwt",
            new ValidationParameters { Options = ValidationOptions.Default & ~ValidationOptions.ValidateLifetime });

        Assert.True(result.TryGetSuccess(out _));

        // The store is not consulted at all, so this cannot pass by the cutoff happening to be absent.
        _cutoffs.Verify(
            c => c.GetCutoffAsync(
                It.IsAny<RevocationScope>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
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


    /// <summary>
    /// The real cutoff checker over the mocked stores, not a stub of it: what these tests are about is the
    /// decision it makes, so a stub told to return the right answer would measure nothing.
    /// </summary>
    private IRevocationCutoffChecker CutoffChecker(TimeSpan skew) => new RevocationCutoffChecker(
        NullLogger<RevocationCutoffChecker>.Instance,
        _cutoffs.Object,
        _issuers.Object,
        Options.Create(new OidcOptions { RevocationCutoffSkew = skew }),
        _clients.Object,
        SubjectConverter);

    private static JsonWebToken RefreshToken(string? grantId) => new()
    {
        Payload =
        {
            Issuer = Issuer,
            JwtId = ActiveJwtId,
            ExpiresAt = Expiry,
            GrantId = grantId,
            Subject = Subject,
            SessionId = SessionId,
            IssuedAt = IssuedAt,
        }
    };

    /// <summary>
    /// A token this server did not issue escapes the cutoff entirely, however its subject reads.
    /// </summary>
    /// <remarks>
    /// The same validator sees assertions minted elsewhere - a client's <c>private_key_jwt</c>, where
    /// RFC 7523 Section 3 makes <c>sub</c> the <c>client_id</c>, and grants asserted by a federated issuer.
    /// Those subjects are strings from another namespace, so matching one against a local cutoff refuses a
    /// stranger's token for a revocation that has nothing to do with it. The collision is not hypothetical:
    /// under <c>client_credentials</c> this server's own <c>sub</c> is a <c>client_id</c> too, so revoking a
    /// compromised machine identity would otherwise start refusing that same client's assertions.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_TokenFromAnotherIssuer_IsNotReachedByACutoff()
    {
        SetupInnerReturns(new JsonWebToken
        {
            Payload =
            {
                Issuer = "https://partner.example.net",
                JwtId = ActiveJwtId,
                ExpiresAt = Expiry,
                Subject = Subject,
                IssuedAt = IssuedAt,
            }
        });
        SetupCutoff(RevocationScope.Subject, Subject, Expiry);
        _registry.Setup(r => r.GetStatusAsync(ActiveJwtId)).ReturnsAsync(JsonWebTokenStatus.Unknown);

        var result = await _decorator.ValidateAsync("opaque.assertion.jwt", new ValidationParameters());

        Assert.True(result.TryGetSuccess(out _));

        // Nothing was asked of the cutoff store: a foreign subject is not a principal we record cutoffs for,
        // so the question is not one to ask rather than one to answer negatively.
        _cutoffs.Verify(
            c => c.GetCutoffAsync(
                It.IsAny<RevocationScope>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    /// <summary>
    /// A pairwise pseudonym that cannot be opened is refused rather than let through.
    /// </summary>
    /// <remarks>
    /// This is what a rotated pairwise salt, a moved sector identifier or a deleted client leaves behind.
    /// Falling back to the sealed value would look safe and is the opposite: nobody records a cutoff against
    /// a pseudonym, so the lookup would miss and every affected token would be accepted - a revocation
    /// silently undone for exactly the deployment that chose the stricter privacy setting.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_PairwisePseudonymThatCannotBeOpened_IsRefused()
    {
        var pairwiseClient = new ClientInfo(ClientId)
        {
            SubjectType = SubjectTypes.Pairwise,
            SectorIdentifier = SectorIdentifier,
        };
        _clients.Setup(p => p.TryFindClientAsync(ClientId)).ReturnsAsync(pairwiseClient);

        SetupInnerReturns(new JsonWebToken
        {
            Payload =
            {
                Issuer = Issuer,
                JwtId = ActiveJwtId,
                ExpiresAt = Expiry,

                // Not a pseudonym this converter sealed, so opening it fails - the state a salt rotation
                // leaves every previously issued token in.
                Subject = "not-a-pseudonym-this-server-sealed",
                ClientId = ClientId,
                IssuedAt = IssuedAt,
            }
        });

        var result = await _decorator.ValidateAsync("opaque.at.jwt", new ValidationParameters());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.TokenRevoked, error.Error);
    }

    /// <summary>
    /// A client the store no longer knows leaves the subject unresolvable, and the token is refused.
    /// </summary>
    /// <remarks>
    /// Separate from the case above because the two fail at different steps and only one of them involves
    /// the converter at all - a lookup returning nothing would otherwise read as "not pairwise, carry on".
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_TokenNamingAClientThatIsGone_IsRefused()
    {
        _clients.Setup(p => p.TryFindClientAsync(ClientId)).ReturnsAsync((ClientInfo?)null);

        SetupInnerReturns(new JsonWebToken
        {
            Payload =
            {
                Issuer = Issuer,
                JwtId = ActiveJwtId,
                ExpiresAt = Expiry,
                Subject = Subject,
                ClientId = ClientId,
                IssuedAt = IssuedAt,
            }
        });

        var result = await _decorator.ValidateAsync("opaque.at.jwt", new ValidationParameters());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.TokenRevoked, error.Error);
    }

    /// <summary>
    /// The skew widens what a cutoff catches, so a token stamped slightly after it is still refused.
    /// </summary>
    /// <remarks>
    /// The two instants come from different machines. A token reading as older than it is costs one retry;
    /// a token reading as newer escapes the revocation, and because a refresh rotation carries the original
    /// issue time forward it keeps escaping on every use. Seconds of drift would otherwise become access
    /// that never ends.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_TokenIssuedWithinTheSkewAfterACutoff_IsStillRefused()
    {
        var decorator = new TokenStatusValidatorDecorator(
            _registry.Object,
            CutoffChecker(TimeSpan.FromMinutes(1)),
            _inner.Object);

        SetupInnerReturns(new JsonWebToken
        {
            Payload =
            {
                Issuer = Issuer,
                JwtId = ActiveJwtId,
                ExpiresAt = Expiry,
                Subject = Subject,
                IssuedAt = IssuedAt,
            }
        });

        // Recorded half a minute before this token says it was minted, which is what a lagging clock on the
        // revoking instance looks like from here.
        SetupCutoff(RevocationScope.Subject, Subject, IssuedAt.AddSeconds(-30));

        var result = await decorator.ValidateAsync("opaque.at.jwt", new ValidationParameters());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.TokenRevoked, error.Error);
    }
}
