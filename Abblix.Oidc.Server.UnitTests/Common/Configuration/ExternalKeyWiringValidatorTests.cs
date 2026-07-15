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
using Abblix.Jwt.Encryption;
using Abblix.Jwt.Signing;
using Abblix.Oidc.Server.Common.Configuration;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// Verifies the startup fail-closed guard for external encryption keys: a public-only encryption key with no
/// key-management port, or one naming an algorithm with no external form, is rejected at boot; a correctly
/// wired external encryption key and a purely local configuration validate. Signing keys are not checked at
/// startup (they fail closed at runtime), so their coverage lives with the signing-seam tests, not here.
/// </summary>
public class ExternalKeyWiringValidatorTests
{
    private static readonly RsaJsonWebKey LocalSigningKey =
        JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

    private static JsonWebKey ExternalRsaEncryptionKey()
        => JsonWebKeyFactory
            .CreateRsa(PublicKeyUsages.Encryption, EncryptionAlgorithms.KeyManagement.RsaOaep256)
            .Sanitize(false);

    [Fact]
    public void ExternalEncryptionKey_WithoutKeyEncryptorPort_Fails()
    {
        var validator = new ExternalKeyWiringValidator();
        var options = new OidcOptions { EncryptionKeys = [ExternalRsaEncryptionKey()] };

        Assert.True(validator.Validate(null, options).Failed);
    }

    [Fact]
    public void ExternalEncryptionKey_WithKeyEncryptorPort_Succeeds()
    {
        var validator = new ExternalKeyWiringValidator(externalKeyEncryptor: new Mock<IExternalKeyEncryptor>().Object);
        var options = new OidcOptions { EncryptionKeys = [ExternalRsaEncryptionKey()] };

        Assert.True(validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void ExternalDirectEncryptionKey_FailsClosed_EvenWithPort()
    {
        // Direct key agreement has no external form, so it is rejected even when a port is wired.
        var validator = new ExternalKeyWiringValidator(externalKeyEncryptor: new Mock<IExternalKeyEncryptor>().Object);
        var external = new OctetJsonWebKey { KeyId = "ext-dir", Algorithm = EncryptionAlgorithms.KeyManagement.Dir };
        var options = new OidcOptions { EncryptionKeys = [external] };

        Assert.True(validator.Validate(null, options).Failed);
    }

    [Fact]
    public void PurelyLocalConfiguration_Succeeds_WithNoPorts()
    {
        // Every key carries its secret material, so nothing routes externally and no port is required.
        var validator = new ExternalKeyWiringValidator();
        var options = new OidcOptions
        {
            SigningKeys = [LocalSigningKey],
            EncryptionKeys =
            [
                JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption, EncryptionAlgorithms.KeyManagement.RsaOaep256),
            ],
        };

        Assert.True(validator.Validate(null, options).Succeeded);
    }
}
