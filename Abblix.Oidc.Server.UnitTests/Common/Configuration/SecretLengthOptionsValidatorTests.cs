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

using Abblix.Oidc.Server.Common.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Verifies that <see cref="SecretLengthOptionsValidator"/> rejects a configuration whose
/// secret-bearing lengths fall below the security floor for their kind, while the shipped defaults
/// pass unchanged.
/// </summary>
public class SecretLengthOptionsValidatorTests
{
    private readonly SecretLengthOptionsValidator _validator = new();

    /// <summary>
    /// The shipped defaults are all at or above the floors, so a stock configuration validates.
    /// </summary>
    [Fact]
    public void Validate_DefaultOptions_Succeeds()
    {
        var result = _validator.Validate(null, new OidcOptions());

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    /// <summary>
    /// A client secret below the HS256 HMAC-key floor (RFC 7518 §3.2) must be rejected at startup.
    /// </summary>
    [Fact]
    public void Validate_ClientSecretBelowFloor_Fails()
    {
        var options = new OidcOptions
        {
            NewClientOptions = new NewClientOptions
            {
                ClientSecret = new ClientSecretOptions
                {
                    Length = SecretLengthOptionsValidator.MinimumClientSecretLength - 1,
                },
            },
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains("ClientSecret"));
    }

    /// <summary>
    /// An opaque random secret (here the authorization code) below the guess-resistance floor must
    /// be rejected at startup.
    /// </summary>
    [Fact]
    public void Validate_AuthorizationCodeBelowFloor_Fails()
    {
        var options = new OidcOptions
        {
            AuthorizationCodeLength = SecretLengthOptionsValidator.MinimumRandomSecretLength - 1,
        };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains(nameof(OidcOptions.AuthorizationCodeLength)));
    }
}
