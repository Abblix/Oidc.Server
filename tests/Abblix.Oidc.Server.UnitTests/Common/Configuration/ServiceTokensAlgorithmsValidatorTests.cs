// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
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
        _validator = CreateValidator();
    }

    private static ServiceTokensAlgorithmsValidator CreateValidator(IKeyCustodian? custodian = null)
    {
        var jwtCreator = new Mock<IJsonWebTokenCreator>(MockBehavior.Strict);
        jwtCreator.SetupGet(c => c.SignedResponseAlgorithmsSupported).Returns(RegisteredSigningAlgorithms);
        jwtCreator.SetupGet(c => c.EncryptedResponseAlgorithmsSupported).Returns(RegisteredKeyManagementAlgorithms);

        return new ServiceTokensAlgorithmsValidator(jwtCreator.Object, custodian);
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

    /// <summary>
    /// A host that requires encryption while no key can serve it is refused at startup, naming both the
    /// setting and the way out. Left to run, it would reach issuance and produce a token whose confidentiality
    /// the configuration promises and the output does not carry.
    /// </summary>
    [Fact]
    public void Validate_EncryptRequiredWithoutAnyKey_Fails()
    {
        var options = new OidcOptions();
        options.ServiceTokens.AccessToken.Encrypt = true;

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains("AccessToken.Encrypt is true"));
    }

    /// <summary>
    /// The same requirement validates once a key is configured, which is the whole condition being checked.
    /// </summary>
    [Fact]
    public void Validate_EncryptRequiredWithConfiguredKey_Succeeds()
    {
        var options = new OidcOptions();
        options.ServiceTokens.AccessToken.Encrypt = true;
        options.EncryptionKeys = [new RsaJsonWebKey { KeyId = "enc-key" }];

        var result = _validator.Validate(null, options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    /// <summary>
    /// With an external custodian registered the keys live outside the options, so an empty
    /// <see cref="OidcOptions.EncryptionKeys"/> says nothing about whether a key exists. Refusing here would
    /// reject startup for exactly the deployments that keep their keys in a Vault or Key Vault backend.
    /// </summary>
    [Fact]
    public void Validate_EncryptRequiredWithCustodian_Succeeds()
    {
        var validator = CreateValidator(new Mock<IKeyCustodian>(MockBehavior.Strict).Object);
        var options = new OidcOptions();
        options.ServiceTokens.AccessToken.Encrypt = true;

        var result = validator.Validate(null, options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }

    /// <summary>
    /// A host that never stated a decision keeps starting with no keys configured, which is what separates
    /// "asked to encrypt" from "did not object" and why the setting is nullable. The shipped default is this
    /// state, so refusing it would break every deployment that does not use encryption at all.
    /// </summary>
    [Fact]
    public void Validate_EncryptUnstatedWithoutAnyKey_Succeeds()
    {
        var options = new OidcOptions();

        Assert.Null(options.ServiceTokens.AccessToken.Encrypt);

        var result = _validator.Validate(null, options);

        Assert.True(result.Succeeded, string.Join("; ", result.Failures ?? []));
    }
}
