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

using System.Buffers.Text;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// A JWT whose header or payload repeats a member name must come back as a validation failure,
/// the same as any other malformed token.
/// </summary>
/// <remarks>
/// RFC 7519 Section 4 and RFC 7515 Section 4 leave the recipient a choice: reject duplicates, or use a parser that
/// keeps the lexically last one. What is not on the menu is the third outcome, which is what a lazy parser
/// produces - the parse reports success and the duplicate surfaces much later, as an exception of an unrelated
/// type, from whichever property the caller happens to read first. The token is attacker-supplied, so that
/// exception escapes on a path an attacker chooses.
/// </remarks>
public class DuplicateJsonMemberTests
{
    private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    private static readonly IServiceProvider ServiceProvider = CreateServiceProvider();

    private static IServiceProvider CreateServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

    private static string EncodeBase64Url(string input)
        => Base64Url.EncodeToString(System.Text.Encoding.UTF8.GetBytes(input));

    private static Task<Result<JsonWebToken, JwtValidationError>> Validate(string headerJson, string payloadJson)
    {
        var jwt = $"{EncodeBase64Url(headerJson)}.{EncodeBase64Url(payloadJson)}.";

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = new ValidationParameters
        {
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveIssuerSigningKeys = _ => SigningKey.ToAsync(),
            ResolveTokenDecryptionKeys = _ => AsyncEnumerable.Empty<JsonWebKey>(),
            Options = ValidationOptions.Default & ~ValidationOptions.RequireSignedTokens
                & ~ValidationOptions.ValidateLifetime,
        };

        return validator.ValidateAsync(jwt, parameters);
    }

    private const string ValidPayload = """{"iss":"https://issuer.example.com","aud":"a","sub":"user"}""";

    /// <summary>
    /// A repeated claim name. The first read of any claim is what trips it, so the failure lands on
    /// whichever property the pipeline happens to touch first rather than at the parse.
    /// </summary>
    [Fact]
    public async Task DuplicateClaimName_FailsValidation_WithoutThrowing()
    {
        var result = await Validate(
            """{"alg":"none","typ":"JWT"}""",
            """{"iss":"https://good.example.com","aud":"a","sub":"user","iss":"https://evil.example.com"}""");

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.MalformedToken, error.Error);
    }

    /// <summary>
    /// The same in the JOSE header, where the first read is <c>alg</c> - so this one trips earlier
    /// than the payload case and on a different property.
    /// </summary>
    [Fact]
    public async Task DuplicateHeaderParameter_FailsValidation_WithoutThrowing()
    {
        var result = await Validate(
            """{"alg":"none","typ":"JWT","alg":"RS256"}""",
            ValidPayload);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.MalformedToken, error.Error);
    }

    /// <summary>
    /// A duplicate nested inside a structured claim. Nothing reads it during validation, so it survives
    /// the pipeline and detonates in the consumer instead - the confirmation claim carries the DPoP
    /// thumbprint, which a caller does read.
    /// </summary>
    [Fact]
    public async Task DuplicateMemberInsideStructuredClaim_FailsValidation_WithoutThrowing()
    {
        var result = await Validate(
            """{"alg":"none","typ":"JWT"}""",
            """{"iss":"https://issuer.example.com","aud":"a","sub":"user","cnf":{"jkt":"AAA","jkt":"BBB"}}""");

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.MalformedToken, error.Error);
    }

    /// <summary>
    /// The control: the same shapes without duplicates still validate, so the guard rejects repetition
    /// rather than anything structural it happens to sit next to.
    /// </summary>
    [Fact]
    public async Task NoDuplicates_StillValidates()
    {
        var result = await Validate(
            """{"alg":"none","typ":"JWT"}""",
            """{"iss":"https://issuer.example.com","aud":"a","sub":"user","cnf":{"jkt":"AAA"}}""");

        Assert.True(result.TryGetSuccess(out var token));
        Assert.Equal("user", token.Payload.Subject);
    }
}
