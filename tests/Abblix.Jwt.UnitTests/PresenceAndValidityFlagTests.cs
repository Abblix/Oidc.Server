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

using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// <see cref="ValidationOptions.RequireIssuer"/> and <see cref="ValidationOptions.RequireAudience"/> ask
/// whether a claim is present. Whether its value is acceptable is a different question, asked by
/// <see cref="ValidationOptions.ValidateIssuer"/> and <see cref="ValidationOptions.ValidateAudience"/>.
/// </summary>
/// <remarks>
/// The two used to be one: the validator ran the caller's delegate on either flag, and dereferenced it
/// unconditionally. So the documented use of the presence flag on its own - "requires the issuer claim (iss)
/// to be present" - threw <see cref="InvalidOperationException"/> from inside validation instead of
/// validating, which on a request path reaches the host as a 500 rather than a refusal. Every case below is
/// a shape that used to throw or to run a check nobody asked for.
/// </remarks>
public class PresenceAndValidityFlagTests
{
    private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    private static readonly IServiceProvider ServiceProvider = new ServiceCollection()
        .AddSingleton(TimeProvider.System)
        .AddLogging()
        .AddJsonWebTokens()
        .BuildServiceProvider();

    private static async Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(
        ValidationOptions options,
        bool withIssuer = true,
        bool withAudience = true,
        ValidationParameters.ValidateIssuersDelegate? validateIssuer = null,
        ValidationParameters.ValidateAudienceDelegate? validateAudience = null)
    {
        var token = new JsonWebToken { Header = { Algorithm = SigningAlgorithms.RS256 } };
        if (withIssuer)
            token.Payload.Issuer = "https://auth.example.com";
        if (withAudience)
            token.Payload.Audiences = ["the-client"];

        var jwt = await ServiceProvider.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, SigningKey);

        return await ServiceProvider.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(
            jwt,
            new ValidationParameters
            {
                Options = options,
                ValidateIssuer = validateIssuer,
                ValidateAudience = validateAudience,
                ResolveIssuerSigningKeys = _ => SigningKey.ToAsync(),
            });
    }

    /// <summary>
    /// Asking only that the issuer be present, and supplying no way to judge it, accepts a token that has
    /// one. This is the case the documentation describes and the one that used to throw.
    /// </summary>
    [Fact]
    public async Task RequiringThePresenceOfAnIssuerWithoutJudgingItAcceptsATokenThatHasOne()
    {
        var result = await ValidateAsync(
            ValidationOptions.RequireIssuer | ValidationOptions.RequireValidSignedTokens);

        Assert.False(result.TryGetFailure(out _));
    }

    /// <summary>
    /// The same options refuse a token carrying no issuer at all, which is what the flag is for.
    /// </summary>
    [Fact]
    public async Task RequiringThePresenceOfAnIssuerRefusesATokenWithoutOne()
    {
        var result = await ValidateAsync(
            ValidationOptions.RequireIssuer | ValidationOptions.RequireValidSignedTokens,
            withIssuer: false);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains("Missing issuer", error.ErrorDescription);
    }

    /// <summary>
    /// Asking for the issuer to be judged, and supplying nothing to judge it with, fails the token rather
    /// than the process.
    /// </summary>
    /// <remarks>
    /// A misconfiguration this token cannot survive, but the caller is a request handler and the token is
    /// attacker-supplied: an exception here would be a 500 chosen by whoever sent the token, where a typed
    /// failure is a refusal.
    /// </remarks>
    [Fact]
    public async Task AskingForTheIssuerToBeJudgedWithNothingToJudgeItWithIsAFailureNotAThrow()
    {
        var result = await ValidateAsync(
            ValidationOptions.RequireValidIssuer | ValidationOptions.RequireValidSignedTokens);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains("No issuer validator configured", error.ErrorDescription);
    }

    /// <summary>
    /// A delegate supplied under the validity flag is called, and its refusal is the token's.
    /// </summary>
    [Fact]
    public async Task TheIssuerDelegateIsCalledWhenTheValidityFlagIsSet()
    {
        var asked = false;

        var result = await ValidateAsync(
            ValidationOptions.RequireValidIssuer | ValidationOptions.RequireValidSignedTokens,
            validateIssuer: _ =>
            {
                asked = true;
                return Task.FromResult(false);
            });

        Assert.True(asked);
        Assert.True(result.TryGetFailure(out var error));
        Assert.Contains("Invalid issuer", error.ErrorDescription);
    }

    /// <summary>
    /// A delegate supplied WITHOUT the validity flag is not called, which is what clearing the flag asks for.
    /// </summary>
    /// <remarks>
    /// The half that used to be impossible: a caller deriving its options by subtraction, as the registration
    /// access token validator does with <c>Default &amp; ~ValidateAudience</c>, had its delegate run anyway
    /// because the presence flag was still set. Clearing a flag now means what it says.
    /// </remarks>
    [Fact]
    public async Task TheIssuerDelegateIsNotCalledWhenOnlyPresenceIsRequired()
    {
        var asked = false;

        var result = await ValidateAsync(
            ValidationOptions.RequireIssuer | ValidationOptions.RequireValidSignedTokens,
            validateIssuer: _ =>
            {
                asked = true;
                return Task.FromResult(false);
            });

        Assert.False(asked);
        Assert.False(result.TryGetFailure(out _));
    }

    /// <summary>
    /// The audience flags behave the same way, because they carried the same defect one method down.
    /// </summary>
    [Fact]
    public async Task TheAudienceFlagsSplitThePresenceFromTheJudgement()
    {
        var accepted = await ValidateAsync(
            ValidationOptions.RequireAudience | ValidationOptions.RequireValidSignedTokens);
        Assert.False(accepted.TryGetFailure(out _));

        var missing = await ValidateAsync(
            ValidationOptions.RequireAudience | ValidationOptions.RequireValidSignedTokens,
            withAudience: false);
        Assert.True(missing.TryGetFailure(out var error));
        Assert.Contains("Missing audience", error.ErrorDescription);

        var unjudgeable = await ValidateAsync(
            ValidationOptions.RequireValidAudience | ValidationOptions.RequireValidSignedTokens);
        Assert.True(unjudgeable.TryGetFailure(out var second));
        Assert.Contains("No audience validator configured", second.ErrorDescription);
    }
}
