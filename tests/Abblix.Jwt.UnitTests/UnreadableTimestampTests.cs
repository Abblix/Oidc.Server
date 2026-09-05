// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Text;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// A timestamp claim the payload cannot read is the token's fault, and the answer to a token's fault
/// is a refusal. Before this the typed accessors threw out of the validator, and a request carrying
/// such a token ended in an unhandled exception rather than in an error the sender could act on.
/// </summary>
/// <remarks>
/// Two shapes of unreadable, because they fail in two different places: a number outside the range
/// <see cref="DateTimeOffset"/> can hold fails the conversion, and a string fails the read before
/// any conversion is attempted. A fix catching one of them reads exactly like a fix catching both.
/// </remarks>
public class UnreadableTimestampTests
{
    private static readonly DateTimeOffset Now = new(2027, 1, 1, 12, 0, 0, TimeSpan.Zero);

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
    /// Builds an unsigned token whose payload is written verbatim, so a case can carry a claim value
    /// the typed accessors would never produce.
    /// </summary>
    private static Task<Result<JsonWebToken, JwtValidationError>> Validate(string payloadJson)
    {
        var jwt = EncodeBase64Url("""{"alg":"none"}""") + "." + EncodeBase64Url(payloadJson) + ".";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        return validator.ValidateAsync(jwt, new ValidationParameters
        {
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveIssuerSigningKeys = _ => AsyncEnumerable.Empty<JsonWebKey>(),
            ResolveTokenDecryptionKeys = _ => AsyncEnumerable.Empty<JsonWebKey>(),
            Options = ValidationOptions.ValidateLifetime,
        });
    }

    [Theory]
    [InlineData("""{"exp": 99999999999999}""", "exp")]
    [InlineData("""{"iat": 99999999999999}""", "iat")]
    [InlineData("""{"nbf": 99999999999999}""", "nbf")]
    [InlineData("""{"exp": "tomorrow"}""", "exp")]
    [InlineData("""{"iat": {"seconds": 1}}""", "iat")]
    public async Task ATimestampThePayloadCannotRead_IsRefusedAsMalformedNamingTheClaim(string payload, string claim)
    {
        var result = await Validate(payload);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.MalformedToken, error.Error);
        Assert.Contains(claim, error.ErrorDescription, StringComparison.Ordinal);
    }

    /// <summary>
    /// And a token whose timestamps read is judged on them, or the cases above would be satisfied
    /// by a validator refusing every token as malformed.
    /// </summary>
    [Fact]
    public async Task AReadableTimestamp_IsJudgedRatherThanRefusedAsMalformed()
    {
        var result = await Validate($$"""{"exp": {{Now.AddHours(1).ToUnixTimeSeconds()}}}""");

        Assert.True(result.TryGetSuccess(out _));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
