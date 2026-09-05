// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt;
using Abblix.Jwt.ReplayPrevention;
using Abblix.SecurityEvents.BackChannelLogout;
using Abblix.SecurityEvents.Validation;
using Abblix.Utils;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// A Logout Token must be remembered for as long as it can still be accepted, which is past its
/// own expiry.
/// </summary>
/// <remarks>
/// The profile lets a token in up to the clock tolerance after <c>exp</c>, because the receiver's
/// clock is not the provider's. Reserving until <c>exp</c> alone leaves a window in which the token
/// is still admitted and no longer remembered, so a captured token replays as often as it is posted
/// - and a distributed cache that floors a non-positive lifetime to a few seconds turns that into a
/// permanent hole rather than a brief one.
/// </remarks>
public class LogoutTokenReplayWindowTests
{
    private const string Issuer = "https://op.example.com";
    private const string ClientId = "client_123";

    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1754040000);

    /// <summary>Records what the validator asked to be remembered, and for how long.</summary>
    private sealed class RecordingReplayCache : IReplayCache
    {
        public DateTimeOffset? ReservedUntil { get; private set; }

        public Task<bool> TryReserveAsync(
            string identifier, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
        {
            ReservedUntil = expiresAt;
            return Task.FromResult(true);
        }
    }

    /// <summary>A profile that accepts whatever it is handed, so the case is about the guard alone.</summary>
    private sealed class AcceptingProfile(SecurityEventToken token) : ISecurityEventTokenValidator
    {
        public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
            SecurityEventTokenValidationContext context,
            CancellationToken cancellationToken)
        {
            context.Token = token;
            return ValueTask.FromResult<SecurityEventTokenValidationError?>(null);
        }
    }

    [Fact]
    public async Task TheReservationOutlastsTheExpiry_ByTheClockToleranceTheProfileAllows()
    {
        var expiresAt = Now + TimeSpan.FromMinutes(5);

        var token = new JsonWebToken();
        token.Payload.Issuer = Issuer;
        token.Payload.Audiences = [ClientId];
        token.Payload.JwtId = "jti-1";
        token.Payload.Subject = "user_456";
        token.Payload.IssuedAt = Now;
        token.Payload.ExpiresAt = expiresAt;

        var options = new BackChannelLogoutValidationOptions
        {
            ExpectedAudience = ClientId,
            ExpectedIssuers = [Issuer],
        };

        var cache = new RecordingReplayCache();
        var validator = new LogoutTokenValidator(
            new AcceptingProfile(new SecurityEventToken(token)), options, cache);

        await validator.ValidateAsync("a.b.c", TestContext.Current.CancellationToken);

        Assert.Equal(expiresAt + options.IssuedAtTolerance, cache.ReservedUntil);
    }

    /// <summary>
    /// The token was verified without lifetime handling, so this validator is the first reader of
    /// its expiry - and a value no date can hold is the provider's fault, refused with the failure
    /// every other defect of the token gets rather than thrown out of the intake.
    /// </summary>
    [Fact]
    public async Task AnExpiryOutsideTheRepresentableRange_IsAValidationFailure()
    {
        var token = new JsonWebToken();
        token.Payload.Issuer = Issuer;
        token.Payload.Audiences = [ClientId];
        token.Payload.JwtId = "jti-1";
        token.Payload.Subject = "user_456";
        token.Payload.IssuedAt = Now;
        token.Payload.Json[JwtClaimTypes.ExpiresAt] = 99999999999999L;

        var validator = new LogoutTokenValidator(
            new AcceptingProfile(new SecurityEventToken(token)),
            new BackChannelLogoutValidationOptions { ExpectedAudience = ClientId, ExpectedIssuers = [Issuer] },
            new RecordingReplayCache());

        var failure = await Assert.ThrowsAsync<LogoutTokenValidationException>(
            () => validator.ValidateAsync("a.b.c", TestContext.Current.CancellationToken));

        Assert.Contains(JwtClaimTypes.ExpiresAt, failure.Message, StringComparison.Ordinal);
    }
}
