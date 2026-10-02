// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Xunit;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// The sign request each JWS algorithm turns into. The table behind <see cref="TransitSignRequests"/> is held
/// complete here: every recognized algorithm is either signed or named below as one Transit cannot sign, so an
/// algorithm added to <see cref="SigningAlgorithms.Known"/> fails until somebody decides which it is.
/// </summary>
public class TransitSignRequestsTests
{
    private const string Input = "aW5wdXQ=";
    private const int KeyVersion = 3;

    private static readonly string[] AlgorithmsTransitCannotSign =
    [
        SigningAlgorithms.None,
        SigningAlgorithms.HS256,
        SigningAlgorithms.HS384,
        SigningAlgorithms.HS512,
    ];

    public static TheoryData<string> RecognizedAlgorithms => new(SigningAlgorithms.Known);

    [Theory]
    [MemberData(nameof(RecognizedAlgorithms))]
    public void EveryRecognizedAlgorithm_IsSignedOrRefused(string algorithm)
    {
        if (AlgorithmsTransitCannotSign.Contains(algorithm))
            Assert.Throws<NotSupportedException>(() => TransitSignRequests.For(algorithm, Input, KeyVersion));
        else
            Assert.Equal(KeyVersion, TransitSignRequests.For(algorithm, Input, KeyVersion).KeyVersion);
    }

    [Theory]
    [InlineData(SigningAlgorithms.RS256, "sha2-256", "pkcs1v15", null)]
    [InlineData(SigningAlgorithms.RS384, "sha2-384", "pkcs1v15", null)]
    [InlineData(SigningAlgorithms.RS512, "sha2-512", "pkcs1v15", null)]
    [InlineData(SigningAlgorithms.PS256, "sha2-256", "pss", null)]
    [InlineData(SigningAlgorithms.PS384, "sha2-384", "pss", null)]
    [InlineData(SigningAlgorithms.PS512, "sha2-512", "pss", null)]
    [InlineData(SigningAlgorithms.ES256, "sha2-256", null, "jws")]
    [InlineData(SigningAlgorithms.ES384, "sha2-384", null, "jws")]
    [InlineData(SigningAlgorithms.ES512, "sha2-512", null, "jws")]
    public void Request_CarriesDigestAndSignatureForm(
        string algorithm,
        string hashAlgorithm,
        string? signatureAlgorithm,
        string? marshalingAlgorithm)
    {
        var request = TransitSignRequests.For(algorithm, Input, KeyVersion);

        Assert.Equal(Input, request.Input);
        Assert.False(request.Prehashed);
        Assert.Equal(hashAlgorithm, request.HashAlgorithm);
        Assert.Equal(signatureAlgorithm, request.SignatureAlgorithm);
        Assert.Equal(marshalingAlgorithm, request.MarshalingAlgorithm);
    }
}
