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

    /// <summary>
    /// The tolerance belongs to the clock, so a case that is about a different tolerance gets a
    /// different container rather than passing a value per call.
    /// </summary>
    private static IServiceProvider CreateServiceProvider(TimeSpan tolerance)
    {
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(new FixedTimeProvider(Now));
        services.AddLogging();
        services.AddJsonWebTokens();
        services.Configure<ClockOffsetOptions>(o => o.Tolerance = tolerance);
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
        TimeSpan? tolerance = null)
    {
        var claims = new Dictionary<string, object>();
        if (issuedAt.HasValue) claims["iat"] = issuedAt.Value.ToUnixTimeSeconds();
        if (notBefore.HasValue) claims["nbf"] = notBefore.Value.ToUnixTimeSeconds();
        if (expiresAt.HasValue) claims["exp"] = expiresAt.Value.ToUnixTimeSeconds();

        var jwt = EncodeBase64Url("""{"alg":"none"}""")
                  + "." + EncodeBase64Url(JsonSerializer.Serialize(claims)) + ".";

        var validator = CreateServiceProvider(tolerance ?? TimeSpan.FromSeconds(10))
            .GetRequiredService<IJsonWebTokenValidator>();
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
            tolerance: TimeSpan.FromSeconds(10));

        Assert.True(result.TryGetSuccess(out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(10)]
    public async Task NotBeforeWithinTheTolerance_IsAccepted(int secondsAhead)
    {
        var result = await Validate(
            notBefore: Now.AddSeconds(secondsAhead),
            expiresAt: Now.AddHours(1),
            tolerance: TimeSpan.FromSeconds(10));

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// The second half, which the first says nothing about: past the window the token is refused.
    /// Ninety seconds is beyond the ceiling a tolerance may be set to at all, so no configuration
    /// of the server accepts it.
    /// </summary>
    [Theory]
    [InlineData(11)]
    [InlineData(90)]
    public async Task IssuedAtBeyondTheTolerance_IsRefused(int secondsAhead)
    {
        var result = await Validate(
            issuedAt: Now.AddSeconds(secondsAhead),
            tolerance: TimeSpan.FromSeconds(10));

        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains("future", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(11)]
    [InlineData(90)]
    public async Task NotBeforeBeyondTheTolerance_IsRefused(int secondsAhead)
    {
        var result = await Validate(
            notBefore: Now.AddSeconds(secondsAhead),
            expiresAt: Now.AddHours(1),
            tolerance: TimeSpan.FromSeconds(10));

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
        var result = await Validate(issuedAt: Now.AddSeconds(90));

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
        Assert.True((await Validate(issuedAt: Now, tolerance: TimeSpan.Zero)).TryGetSuccess(out _));
        Assert.True((await Validate(issuedAt: Now.AddSeconds(1), tolerance: TimeSpan.Zero))
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
            issuedAt: Now.AddMinutes(5),
            notBefore: Now.AddMinutes(5),
            expiresAt: Now.AddHours(1));

        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains("not yet valid", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
