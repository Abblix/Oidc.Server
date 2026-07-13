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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Verifies that <see cref="ServiceTokensAlgorithmsValidator"/> accepts a configuration whose service-token
/// signing and encryption algorithms are among the registered ones, and rejects one that names an algorithm
/// no registered signer or encryptor can produce.
/// </summary>
public class ServiceTokensAlgorithmsValidatorTests
{
    private static readonly string[] RegisteredSigningAlgorithms =
        [SigningAlgorithms.RS256, SigningAlgorithms.RS384, SigningAlgorithms.ES256];

    private static readonly string[] RegisteredKeyManagementAlgorithms =
        [EncryptionAlgorithms.KeyManagement.RsaOaep256, EncryptionAlgorithms.KeyManagement.RsaOaep];

    private readonly ServiceTokensAlgorithmsValidator _validator;

    public ServiceTokensAlgorithmsValidatorTests()
    {
        var jwtCreator = new Mock<IJsonWebTokenCreator>(MockBehavior.Strict);
        jwtCreator.SetupGet(c => c.SignedResponseAlgorithmsSupported).Returns(RegisteredSigningAlgorithms);
        jwtCreator.SetupGet(c => c.EncryptedResponseAlgorithmsSupported).Returns(RegisteredKeyManagementAlgorithms);

        _validator = new ServiceTokensAlgorithmsValidator(jwtCreator.Object);
    }

    /// <summary>
    /// The shipped defaults sign every service token with RS256 (a registered algorithm) and encrypt none,
    /// so a stock configuration validates.
    /// </summary>
    [Fact]
    public void Validate_DefaultOptions_Succeeds()
    {
        var result = _validator.Validate(null, new OidcOptions());

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    /// <summary>
    /// A signing algorithm no registered signer can produce must be rejected at startup rather than failing
    /// per-request at issuance.
    /// </summary>
    [Fact]
    public void Validate_UnknownSigningAlgorithm_Fails()
    {
        var options = new OidcOptions();
        options.ServiceTokens.AccessToken.Signing.Algorithm = "made-up-alg";

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains("AccessToken.Signing.Algorithm"));
    }

    /// <summary>
    /// A key-management algorithm no registered encryptor can produce must be rejected at startup.
    /// </summary>
    [Fact]
    public void Validate_UnknownEncryptionAlgorithm_Fails()
    {
        var options = new OidcOptions();
        options.ServiceTokens.RefreshToken.Encryption = new JwtEncryptionSettings { Algorithm = "made-up-alg" };

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains("RefreshToken.Encryption.Algorithm"));
    }

    /// <summary>
    /// A configuration whose signing and encryption algorithms are both registered validates, including a
    /// derive-from-key encryption block that leaves the algorithm unset.
    /// </summary>
    [Fact]
    public void Validate_RegisteredExplicitAlgorithms_Succeeds()
    {
        var options = new OidcOptions();
        options.ServiceTokens.AccessToken.Signing.Algorithm = SigningAlgorithms.ES256;
        options.ServiceTokens.AccessToken.Encryption = new JwtEncryptionSettings
        {
            Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256,
        };
        options.ServiceTokens.RefreshToken.Encryption = new JwtEncryptionSettings(); // derive-from-key, Algorithm null

        var result = _validator.Validate(null, options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }
}
