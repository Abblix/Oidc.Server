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

using System;
using System.Text;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// A client authenticating with <c>client_secret_jwt</c> (OpenID Connect Core §9) signs its
/// assertion with the client secret as the HMAC key. Per RFC 7518 §3.2 an HS256 key must be at
/// least 32 bytes, and the JWT layer enforces that floor. This locks the default DCR-issued secret
/// length to a value whose UTF-8 encoding is usable as an HS256 key, so a client that received a
/// default secret can actually authenticate with it - the mismatch that the mocked
/// <c>ClientSecretJwtAuthenticator</c> unit tests could not surface.
/// </summary>
public class ClientSecretHmacKeyLengthTests
{
    private static readonly IServiceProvider Jwt = BuildJwtServices();

    private static IServiceProvider BuildJwtServices()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// The default client secret, encoded to UTF-8 as an HMAC key, must satisfy the RFC 7518 §3.2
    /// HS256 floor (32 bytes). A shorter default (as before, 16 characters) leaves every
    /// default-secret client unable to use HS256 client_secret_jwt at all.
    /// </summary>
    [Fact]
    public void DefaultSecret_UsableAsHs256Key()
    {
        var secret = new ClientSecretGenerator().GenerateClientSecret(new ClientSecretOptions().Length);
        Assert.True(
            Encoding.UTF8.GetBytes(secret).Length >= 32,
            $"Default client secret is {Encoding.UTF8.GetBytes(secret).Length} bytes, below the 32-byte HS256 key floor.");
    }

    /// <summary>
    /// End to end through the real JWT stack: a client_secret_jwt assertion signed with a
    /// default-length secret as its HS256 key must both sign and verify. With a below-floor secret
    /// the signer rejects the key, so a default-secret client cannot produce a usable assertion.
    /// </summary>
    [Fact]
    public async Task DefaultSecret_SignsAndVerifiesHs256Assertion()
    {
        var secret = new ClientSecretGenerator().GenerateClientSecret(new ClientSecretOptions().Length);
        var key = new OctetJsonWebKey
        {
            Algorithm = SigningAlgorithms.HS256,
            KeyValue = Encoding.UTF8.GetBytes(secret),
        };

        var issuedAt = TimeProvider.System.GetUtcNow();
        var assertion = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.HS256 },
            Payload =
            {
                JwtId = System.Guid.NewGuid().ToString("N"),
                Issuer = "client-a",
                Subject = "client-a",
                Audiences = ["https://auth.example.com/token"],
                IssuedAt = issuedAt,
                NotBefore = issuedAt,
                ExpiresAt = issuedAt + System.TimeSpan.FromMinutes(5),
            },
        };

        var creator = Jwt.GetRequiredService<IJsonWebTokenCreator>();
        var jws = await creator.IssueAsync(assertion, key);

        var validator = Jwt.GetRequiredService<IJsonWebTokenValidator>();
        var result = await validator.ValidateAsync(jws, new ValidationParameters
        {
            Options = ValidationOptions.RequireValidSignedTokens,
            ResolveIssuerSigningKeys = _ => ((JsonWebKey)key).ToAsync(),
        });

        Assert.True(result.TryGetSuccess(out _),
            result.TryGetFailure(out var error) ? error.ErrorDescription : "Validation failed");
    }
}
