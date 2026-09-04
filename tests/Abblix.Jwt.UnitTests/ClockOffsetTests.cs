// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using Abblix.Utils;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Two clocks a few hundred milliseconds apart are enough to have a freshly minted token refused as
/// created in the future, and the tolerance for that is a window in both directions of the same
/// sentence.
/// </summary>
/// <remarks>
/// FAPI 2.0 Security Profile section 5.3.2.1: a server "shall accept JWTs with an <c>iat</c> or
/// <c>nbf</c> timestamp between 0 and 10 seconds in the future but shall reject JWTs with an
/// <c>iat</c> or <c>nbf</c> timestamp greater than 60 seconds in the future". That is one sentence
/// carrying two requirements, so each is driven by its own case here: accepting inside the window is
/// not evidence about refusing outside it, and a check that refused everything would satisfy the
/// second half while breaking the first.
/// </remarks>
public class ClockOffsetTests
{
    private static readonly DateTimeOffset Now =
        new(2027, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static readonly IServiceProvider ServiceProvider = CreateServiceProvider();

    private static IServiceProvider CreateServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(new FixedTimeProvider(Now));
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

    private static string EncodeBase64Url(string input)
        => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(input));

    /// <summary>
    /// Builds an unsigned token carrying exactly the timestamps a case is about, so that a case
    /// about <c>iat</c> cannot pass or fail on <c>nbf</c>.
    /// </summary>
    private static Task<Result<JsonWebToken, JwtValidationError>> Validate(
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? expiresAt = null,
        TimeSpan? skew = null,
        TimeSpan? ceiling = null)
    {
        var claims = new Dictionary<string, object>();
        if (issuedAt.HasValue) claims["iat"] = issuedAt.Value.ToUnixTimeSeconds();
        if (notBefore.HasValue) claims["nbf"] = notBefore.Value.ToUnixTimeSeconds();
        if (expiresAt.HasValue) claims["exp"] = expiresAt.Value.ToUnixTimeSeconds();

        var jwt = EncodeBase64Url("""{"alg":"none"}""")
                  + "." + EncodeBase64Url(JsonSerializer.Serialize(claims)) + ".";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = new ValidationParameters
        {
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveIssuerSigningKeys = _ => AsyncEnumerable.Empty<JsonWebKey>(),
            ResolveTokenDecryptionKeys = _ => AsyncEnumerable.Empty<JsonWebKey>(),
            // Lifetime alone: the tokens here carry no iss, aud or signature, and requiring any of
            // those would refuse them for a reason that is not what these cases are about.
            Options = ValidationOptions.ValidateLifetime,
        };

        // Left alone when the case is about the DEFAULT, so that a case relying on it cannot be
        // satisfied by a value this helper supplied. A ceiling is held against whichever value is in
        // force, the default included, which is what a caller under a bounding profile does.
        if (skew.HasValue)
            parameters.ClockSkew = skew.Value;

        if (ceiling.HasValue)
            parameters.ClockSkew = parameters.ClockSkew.BoundedBy(ceiling);

        return validator.ValidateAsync(jwt, parameters);
    }

    /// <summary>
    /// The first half: inside the window the token is accepted, for both timestamps the
    /// specification names.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(10)]
    public async Task IssuedAtWithinTheTolerance_IsAccepted(int secondsAhead)
    {
        var result = await Validate(
            issuedAt: Now.AddSeconds(secondsAhead),
            skew: TimeSpan.FromSeconds(10));

        Assert.True(result.TryGetSuccess(out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(20)]
    [InlineData(30)]
    public async Task NotBeforeWithinTheTolerance_IsAccepted(int secondsAhead)
    {
        // A value the default does not supply, so the row measures the skew the caller asked for
        // rather than the one every other case would have got anyway.
        var result = await Validate(
            notBefore: Now.AddSeconds(secondsAhead),
            expiresAt: Now.AddHours(1),
            skew: TimeSpan.FromSeconds(30));

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// The second half, which the first says nothing about: past the window the token is refused.
    /// The window here is the skew this case asks for, not a ceiling - a ceiling is what a profile
    /// adds on top, and the cases for it are further down.
    /// </summary>
    [Theory]
    [InlineData(11)]
    [InlineData(90)]
    public async Task IssuedAtBeyondTheTolerance_IsRefused(int secondsAhead)
    {
        var result = await Validate(
            issuedAt: Now.AddSeconds(secondsAhead),
            skew: TimeSpan.FromSeconds(10));

        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains("future", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(31)]
    [InlineData(90)]
    public async Task NotBeforeBeyondTheTolerance_IsRefused(int secondsAhead)
    {
        var result = await Validate(
            notBefore: Now.AddSeconds(secondsAhead),
            expiresAt: Now.AddHours(1),
            skew: TimeSpan.FromSeconds(30));

        Assert.True(result.TryGetFailure(out _));
    }

    /// <summary>
    /// A token carrying <c>iat</c> and nothing else is still checked. Before this the lifetime pass
    /// returned early when neither <c>nbf</c> nor <c>exp</c> was present, so exactly this token -
    /// the shape a client assertion takes when it names only when it was minted - skipped every
    /// comparison.
    /// </summary>
    [Fact]
    public async Task IssuedAtAloneIsStillChecked()
    {
        var result = await Validate(issuedAt: Now.AddMinutes(10));

        Assert.True(result.TryGetFailure(out _));
    }

    /// <summary>
    /// An <c>iat</c> in the past is not this check's business at any distance: how old a token may
    /// be is answered by <c>exp</c> or by the caller's own maximum age, and refusing here would
    /// break every long-lived token this validator also serves.
    /// </summary>
    [Fact]
    public async Task IssuedAtInThePast_IsAccepted()
    {
        var result = await Validate(issuedAt: Now.AddYears(-1));

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// With no tolerance the window closes rather than inverting: the instant itself is still
    /// inside it, and a second ahead is not.
    /// </summary>
    [Fact]
    public async Task WithoutTolerance_TheInstantItselfIsAccepted()
    {
        Assert.True((await Validate(issuedAt: Now, skew: TimeSpan.Zero)).TryGetSuccess(out _));
        Assert.True((await Validate(issuedAt: Now.AddSeconds(1), skew: TimeSpan.Zero))
            .TryGetFailure(out _));
    }

    /// <summary>
    /// Both timestamps ahead at once, which is the case that pins the ORDER rather than either
    /// check. A post-dated token is what its sender meant to send, and "not yet valid" is the
    /// answer that tells them so; a test driving one refusal at a time passes under either order.
    /// </summary>
    [Fact]
    public async Task NotBeforeAndIssuedAtBothAhead_AnswersAboutNotBefore()
    {
        var result = await Validate(
            issuedAt: Now.AddMinutes(10),
            notBefore: Now.AddMinutes(10),
            expiresAt: Now.AddHours(1));

        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains("not yet valid", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The case that measures the DEFAULT: no skew is supplied, so the answer comes from the
    /// validation parameters themselves, and it is NONE. A tolerance granted to a caller that never
    /// asked would widen an expiry check for everyone enforcing a deadline of their own, which is
    /// what most callers of this type are doing - so a deployment-wide answer belongs to the
    /// security profile a host opts into, and a number a profile requires is the profile's to
    /// supply.
    ///
    /// The instant itself is inside the window, so this cannot be satisfied by a validator that
    /// refuses everything.
    /// </summary>
    [Theory]
    [InlineData(0, true)]
    [InlineData(1, false)]
    [InlineData(300, false)]
    public async Task TheDefaultTolerance_IsNone(int secondsAhead, bool accepted)
    {
        var result = await Validate(issuedAt: Now.AddSeconds(secondsAhead));

        Assert.Equal(accepted, result.TryGetSuccess(out _));
    }

    /// <summary>
    /// The reject half of FAPI 2.0 section 5.3.2.1 - "shall reject JWTs with an iat or nbf timestamp
    /// greater than 60 seconds in the future" - holds against a caller asking for more. Note 3 gives
    /// the reason the number is in the specification at all: "to prevent implementations switching
    /// off iat and nbf checks completely", which is a property of this validator rather than a
    /// default somebody may edit.
    /// </summary>
    [Theory]
    [InlineData(60, true)]
    [InlineData(61, false)]
    [InlineData(240, false)]
    public async Task UnderACeiling_AheadOfItIsRefusedWhateverSkewIsAsked(int secondsAhead, bool accepted)
    {
        var result = await Validate(
            issuedAt: Now.AddSeconds(secondsAhead),
            skew: TimeSpan.FromMinutes(5),
            ceiling: TimeSpan.FromSeconds(60));

        Assert.Equal(accepted, result.TryGetSuccess(out _));
    }

    /// <summary>
    /// And without one the skew is the whole answer, which is what a deployment outside a profile
    /// that bounds this is entitled to: RFC 7523 Section 3 allows for clock skew and names no bound.
    /// Without this row the case above would be satisfied by a ceiling applied unconditionally.
    /// </summary>
    [Theory]
    [InlineData(61)]
    [InlineData(240)]
    public async Task WithNoCeiling_TheWholeSkewIsAllowedAhead(int secondsAhead)
    {
        var result = await Validate(
            issuedAt: Now.AddSeconds(secondsAhead),
            skew: TimeSpan.FromMinutes(5));

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// The ceiling holds the backward direction too: a profile distrusting a clock past some point
    /// one way has no reason to trust it further the other. A caller asking for more than the
    /// ceiling past an expiry gets the ceiling, and anything beyond it is refused.
    /// </summary>
    [Theory]
    [InlineData(-59, true)]
    [InlineData(-61, false)]
    [InlineData(-240, false)]
    public async Task UnderACeiling_PastExpiryIsBoundedToo(int secondsPastExpiry, bool accepted)
    {
        var result = await Validate(
            expiresAt: Now.AddSeconds(secondsPastExpiry),
            skew: TimeSpan.FromMinutes(5),
            ceiling: TimeSpan.FromSeconds(60));

        Assert.Equal(accepted, result.TryGetSuccess(out _));
    }

    /// <summary>
    /// And without a ceiling the backward window is the whole skew, which is what keeps the case
    /// above from being satisfied by a bound applied unconditionally: no specification in play says
    /// how long an issued token stays usable past its expiry, so a caller asking for a window there
    /// gets the window it asked for.
    /// </summary>
    [Fact]
    public async Task PastExpiry_TheWholeSkewApplies()
    {
        var result = await Validate(
            expiresAt: Now.AddMinutes(-4),
            skew: TimeSpan.FromMinutes(5));

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// And the other end of that direction, without which the row above would be satisfied by a
    /// backward window with no bound at all. Each direction needs both an acceptance and a refusal,
    /// at the default and at a value the caller asked for.
    /// </summary>
    [Fact]
    public async Task PastExpiry_BeyondTheSkew_IsRefused()
    {
        var result = await Validate(
            expiresAt: Now.AddMinutes(-6),
            skew: TimeSpan.FromMinutes(5));

        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains("expired", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// And the default is none in that direction too, which is half of the same criterion: naming
    /// it forward and leaving the other side unmeasured would answer only half the property.
    ///
    /// The boundary differs from the forward one and is measured rather than assumed: expiry is
    /// compared with <c>&lt;=</c>, so a token at its expiry is already expired, while one at the
    /// forward limit is still accepted.
    /// </summary>
    [Theory]
    [InlineData(-1, true)]
    [InlineData(0, false)]
    [InlineData(300, false)]
    public async Task TheDefaultTolerance_GrantsNothingPastExpiryEither(int secondsPast, bool accepted)
    {
        var result = await Validate(expiresAt: Now.AddSeconds(-secondsPast));

        Assert.Equal(accepted, result.TryGetSuccess(out _));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
