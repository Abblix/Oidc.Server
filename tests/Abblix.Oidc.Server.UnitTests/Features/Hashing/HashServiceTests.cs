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
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Abblix.Oidc.Server.Features.Hashing;
using Xunit;
using HashAlgorithm = Abblix.Oidc.Server.Features.Hashing.HashAlgorithm;

namespace Abblix.Oidc.Server.UnitTests.Features.Hashing;

/// <summary>
/// Unit tests for <see cref="HashService"/> verifying hashing functionality
/// for PKCE code challenges and client secret hashing per OAuth 2.0 specification.
/// </summary>
public class HashServiceTests
{
    private readonly HashService _service;

    public HashServiceTests()
    {
        _service = new HashService();
    }

    /// <summary>
    /// Verifies that SHA256 returns 32 bytes (256 bits).
    /// Per SHA-256 specification, output is always 256 bits.
    /// </summary>
    [Fact]
    public void Sha_WithSha256_ShouldReturn32Bytes()
    {
        // Arrange
        var data = "test_data";

        // Act
        var result = _service.Sha(HashAlgorithm.Sha256, data);

        // Assert
        Assert.Equal(32, result.Length);
    }

    /// <summary>
    /// Verifies that SHA512 returns 64 bytes (512 bits).
    /// Per SHA-512 specification, output is always 512 bits.
    /// </summary>
    [Fact]
    public void Sha_WithSha512_ShouldReturn64Bytes()
    {
        // Arrange
        var data = "test_data";

        // Act
        var result = _service.Sha(HashAlgorithm.Sha512, data);

        // Assert
        Assert.Equal(64, result.Length);
    }

    /// <summary>
    /// Verifies that SHA256 produces deterministic output.
    /// Per cryptographic hash requirements, same input must produce same hash.
    /// </summary>
    [Fact]
    public void Sha_WithSha256_ShouldProduceDeterministicOutput()
    {
        // Arrange
        var data = "test_data";

        // Act
        var result1 = _service.Sha(HashAlgorithm.Sha256, data);
        var result2 = _service.Sha(HashAlgorithm.Sha256, data);

        // Assert
        Assert.Equal(result1, result2);
    }

    /// <summary>
    /// Verifies that SHA512 produces deterministic output.
    /// Per cryptographic hash requirements, same input must produce same hash.
    /// </summary>
    [Fact]
    public void Sha_WithSha512_ShouldProduceDeterministicOutput()
    {
        // Arrange
        var data = "test_data";

        // Act
        var result1 = _service.Sha(HashAlgorithm.Sha512, data);
        var result2 = _service.Sha(HashAlgorithm.Sha512, data);

        // Assert
        Assert.Equal(result1, result2);
    }

    /// <summary>
    /// Verifies that different inputs produce different hashes.
    /// Per cryptographic hash collision resistance property.
    /// </summary>
    [Fact]
    public void Sha_WithDifferentInputs_ShouldProduceDifferentHashes()
    {
        // Arrange
        var data1 = "test_data_1";
        var data2 = "test_data_2";

        // Act
        var result1 = _service.Sha(HashAlgorithm.Sha256, data1);
        var result2 = _service.Sha(HashAlgorithm.Sha256, data2);

        // Assert
        Assert.NotEqual(result1, result2);
    }

    /// <summary>
    /// Verifies that SHA256 and SHA512 produce different outputs for same input.
    /// Different algorithms must produce different hashes.
    /// </summary>
    [Fact]
    public void Sha_DifferentAlgorithms_ShouldProduceDifferentHashes()
    {
        // Arrange
        var data = "test_data";

        // Act
        var sha256Result = _service.Sha(HashAlgorithm.Sha256, data);
        var sha512Result = _service.Sha(HashAlgorithm.Sha512, data);

        // Assert
        Assert.NotEqual(sha256Result.Length, sha512Result.Length);
        Assert.NotEqual(sha256Result, sha512Result.Take(32).ToArray());
    }

    /// <summary>
    /// Verifies that empty string is hashed correctly.
    /// Per OAuth 2.0, even empty strings must be hashable for PKCE.
    /// </summary>
    [Fact]
    public void Sha_WithEmptyString_ShouldReturnValidHash()
    {
        // Arrange
        var data = string.Empty;

        // Act
        var result = _service.Sha(HashAlgorithm.Sha256, data);

        // Assert
        Assert.Equal(32, result.Length);
        Assert.NotEqual(new byte[32], result); // Should not be all zeros
    }

    /// <summary>
    /// Verifies that single character is hashed correctly.
    /// Tests minimal valid input.
    /// </summary>
    [Fact]
    public void Sha_WithSingleCharacter_ShouldReturnValidHash()
    {
        // Arrange
        var data = "a";

        // Act
        var result = _service.Sha(HashAlgorithm.Sha256, data);

        // Assert
        Assert.Equal(32, result.Length);
    }

    /// <summary>
    /// Verifies that very long string is hashed correctly.
    /// Tests handling of large inputs.
    /// </summary>
    [Fact]
    public void Sha_WithVeryLongString_ShouldReturnValidHash()
    {
        // Arrange
        var data = new string('a', 10000);

        // Act
        var result = _service.Sha(HashAlgorithm.Sha256, data);

        // Assert
        Assert.Equal(32, result.Length);
    }

    /// <summary>
    /// Verifies that special ASCII characters are hashed correctly.
    /// Per OAuth 2.0, code verifiers can contain various ASCII characters.
    /// </summary>
    [Fact]
    public void Sha_WithSpecialCharacters_ShouldReturnValidHash()
    {
        // Arrange
        var data = "!@#$%^&*()_+-=[]{}|;':\",./<>?";

        // Act
        var result = _service.Sha(HashAlgorithm.Sha256, data);

        // Assert
        Assert.Equal(32, result.Length);
    }

    /// <summary>
    /// Verifies that numeric strings are hashed correctly.
    /// Tests digit-only input.
    /// </summary>
    [Fact]
    public void Sha_WithNumericString_ShouldReturnValidHash()
    {
        // Arrange
        var data = "1234567890";

        // Act
        var result = _service.Sha(HashAlgorithm.Sha256, data);

        // Assert
        Assert.Equal(32, result.Length);
    }

    /// <summary>
    /// Verifies that alphanumeric mixed case is hashed correctly.
    /// Per PKCE specification, code verifiers use unreserved characters.
    /// </summary>
    [Fact]
    public void Sha_WithAlphanumericMixedCase_ShouldReturnValidHash()
    {
        // Arrange
        var data = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        // Act
        var result = _service.Sha(HashAlgorithm.Sha256, data);

        // Assert
        Assert.Equal(32, result.Length);
    }

    /// <summary>
    /// Verifies case sensitivity of hashing.
    /// Different cases must produce different hashes.
    /// </summary>
    [Fact]
    public void Sha_IsCaseSensitive()
    {
        // Arrange
        var lowercase = "test";
        var uppercase = "TEST";

        // Act
        var result1 = _service.Sha(HashAlgorithm.Sha256, lowercase);
        var result2 = _service.Sha(HashAlgorithm.Sha256, uppercase);

        // Assert
        Assert.NotEqual(result1, result2);
    }

    /// <summary>
    /// Verifies that unsupported algorithm throws ArgumentOutOfRangeException.
    /// Per defensive programming, invalid enums must be rejected.
    /// </summary>
    [Fact]
    public void Sha_WithUnsupportedAlgorithm_ShouldThrowArgumentOutOfRangeException()
    {
        // Arrange
        var data = "test_data";
        var invalidAlgorithm = (HashAlgorithm)999;

        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(
            () => _service.Sha(invalidAlgorithm, data));

        Assert.Equal("algorithm", exception.ParamName);
        Assert.Contains("not supported", exception.Message);
    }

    /// <summary>
    /// Verifies SHA256 against known test vector.
    /// Per SHA-256 specification, validates correct implementation.
    /// </summary>
    [Fact]
    public void Sha_WithSha256_ShouldMatchKnownTestVector()
    {
        // Arrange - SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        var data = "abc";
        var expected = Convert.FromHexString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        // Act
        var result = _service.Sha(HashAlgorithm.Sha256, data);

        // Assert
        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Verifies SHA512 against known test vector.
    /// Per SHA-512 specification, validates correct implementation.
    /// </summary>
    [Fact]
    public void Sha_WithSha512_ShouldMatchKnownTestVector()
    {
        // Arrange - SHA512("abc") = ddaf35a193617aba...
        var data = "abc";
        var expected = Convert.FromHexString(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

        // Act
        var result = _service.Sha(HashAlgorithm.Sha512, data);

        // Assert
        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Verifies that whitespace is significant in hashing.
    /// Spaces and tabs must affect hash output.
    /// </summary>
    [Fact]
    public void Sha_WithWhitespace_ShouldBeSensitiveToSpaces()
    {
        // Arrange
        var noSpace = "test";
        var withSpace = "test ";

        // Act
        var result1 = _service.Sha(HashAlgorithm.Sha256, noSpace);
        var result2 = _service.Sha(HashAlgorithm.Sha256, withSpace);

        // Assert
        Assert.NotEqual(result1, result2);
    }

    /// <summary>
    /// Verifies that newlines are handled correctly.
    /// Multi-line strings must be hashable.
    /// </summary>
    [Fact]
    public void Sha_WithNewlines_ShouldReturnValidHash()
    {
        // Arrange
        var data = "line1\nline2\nline3";

        // Act
        var result = _service.Sha(HashAlgorithm.Sha256, data);

        // Assert
        Assert.Equal(32, result.Length);
    }

    /// <summary>
    /// Verifies ASCII encoding is used correctly.
    /// Non-ASCII characters should be handled by ASCII encoding rules.
    /// </summary>
    [Fact]
    public void Sha_UsesAsciiEncoding()
    {
        // Arrange
        var data = "test";
        var expectedBytes = Encoding.ASCII.GetBytes(data);
        var expectedHash = SHA256.HashData(expectedBytes);

        // Act
        var result = _service.Sha(HashAlgorithm.Sha256, data);

        // Assert
        Assert.Equal(expectedHash, result);
    }

    /// <summary>
    /// Verifies PKCE code challenge scenario.
    /// Per RFC 7636, code_challenge = BASE64URL(SHA256(ASCII(code_verifier))).
    /// </summary>
    [Fact]
    public void Sha_PkceCodeChallenge_ShouldWorkCorrectly()
    {
        // Arrange - Example from RFC 7636
        var codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        // Act
        var result = _service.Sha(HashAlgorithm.Sha256, codeVerifier);

        // Assert
        Assert.Equal(32, result.Length);
        // Result should be base64url encoded in actual usage
        Assert.NotEqual(new byte[32], result);
    }

    /// <summary>
    /// Verifies client secret hashing scenario.
    /// Per OAuth 2.0, client secrets should be hashed before storage.
    /// </summary>
    [Fact]
    public void Sha_ClientSecretHashing_ShouldWorkCorrectly()
    {
        // Arrange
        var clientSecret = "super_secret_client_secret_12345";

        // Act
        var result = _service.Sha(HashAlgorithm.Sha512, clientSecret);

        // Assert
        Assert.Equal(64, result.Length);
        Assert.NotEqual(new byte[64], result);
    }

    /// <summary>
    /// Verifies that hash output is non-zero.
    /// Valid hashes should not be all zeros.
    /// </summary>
    [Fact]
    public void Sha_ShouldNotReturnAllZeros()
    {
        // Arrange
        var data = "test";

        // Act
        var result = _service.Sha(HashAlgorithm.Sha256, data);

        // Assert
        Assert.NotEqual(new byte[32], result);
        Assert.Contains(result, b => b != 0);
    }

    /// <summary>
    /// Verifies URL-safe characters (used in PKCE).
    /// Per RFC 7636, unreserved characters: A-Z a-z 0-9 - . _ ~
    /// </summary>
    [Fact]
    public void Sha_WithUrlSafeCharacters_ShouldReturnValidHash()
    {
        // Arrange
        var data = "ABCabc123-._~";

        // Act
        var result = _service.Sha(HashAlgorithm.Sha256, data);

        // Assert
        Assert.Equal(32, result.Length);
    }

    /// <summary>
    /// Verifies handling of repeated characters.
    /// Tests pattern sensitivity.
    /// </summary>
    [Fact]
    public void Sha_WithRepeatedCharacters_ShouldReturnValidHash()
    {
        // Arrange
        var data = "aaaaaaaaaa";

        // Act
        var result = _service.Sha(HashAlgorithm.Sha256, data);

        // Assert
        Assert.Equal(32, result.Length);
    }

    /// <summary>
    /// Verifies that similar strings produce different hashes.
    /// Tests avalanche effect of cryptographic hash functions.
    /// </summary>
    [Fact]
    public void Sha_SimilarStrings_ShouldProduceDifferentHashes()
    {
        // Arrange
        var data1 = "test1";
        var data2 = "test2";

        // Act
        var result1 = _service.Sha(HashAlgorithm.Sha256, data1);
        var result2 = _service.Sha(HashAlgorithm.Sha256, data2);

        // Assert
        Assert.NotEqual(result1, result2);
        // Should differ in many bits (avalanche effect)
        var diffBits = result1.Zip(result2, (a, b) => (byte)(a ^ b)).Sum(x => BitCount(x));
        Assert.True(diffBits > 100, "Avalanche effect: many bits should differ");
    }

    private static int BitCount(byte b)
    {
        var count = 0;
        while (b != 0)
        {
            count += b & 1;
            b >>= 1;
        }
        return count;
    }
}
