// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Formatters;

/// <summary>
/// The one door to <see cref="IJsonWebTokenCreator"/> for what this server signs or encrypts. FAPI 1.0 Part 2 section
/// 8.6: "For JWS, both clients and authorization servers shall use PS256 or ES256 algorithms"; section 8.6.1: "For JWE,
/// both clients and authorization servers shall not use the RSA1_5 algorithm"; FAPI 2.0 section 5.4.1 "when creating
/// or processing JWTs". It judges the algorithm finally handed to the creator, whichever path chose it.
/// </summary>
public class ProfiledJwtIssuerTests
{
    private static readonly SecurityProfileRequirements Fapi1 =
        SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi1Advanced);

    private static readonly SecurityProfileRequirements Unprofiled =
        SecurityProfileRequirements.Resolve(ClientSecurityProfile.None);

    private readonly Mock<IJsonWebTokenCreator> _creator = new(MockBehavior.Strict);
    private readonly JsonWebKey _signingKey = new RsaJsonWebKey { KeyId = "sig" };
    private readonly JsonWebKey _encryptionKey = new RsaJsonWebKey { KeyId = "enc" };

    private ProfiledJwtIssuer Issuer()
    {
        _creator
            .Setup(c => c.IssueAsync(
                It.IsAny<JsonWebToken>(), It.IsAny<JsonWebKey?>(), It.IsAny<JsonWebKey?>(), It.IsAny<string>(),
                It.IsAny<string>()))
            .ReturnsAsync("issued");
        return new ProfiledJwtIssuer(_creator.Object);
    }

    private static JsonWebToken Token(string algorithm) => new() { Header = { Algorithm = algorithm } };

    [Theory]
    [InlineData(SigningAlgorithms.RS256, false)]
    [InlineData(SigningAlgorithms.PS256, true)]
    [InlineData(SigningAlgorithms.ES256, true)]
    public async Task TheSignatureAlgorithm_IsJudgedByTheProfile(string algorithm, bool issued)
    {
        var issuer = Issuer();

        var issue = () => issuer.IssueAsync(Fapi1, Token(algorithm), _signingKey);

        if (issued)
            Assert.Equal("issued", await issue());
        else
            await Assert.ThrowsAsync<AlgorithmRefusedByProfileException>(issue);
    }

    [Theory]
    [InlineData(EncryptionAlgorithms.KeyManagement.Rsa1_5, false)]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, true)]
    public async Task TheKeyManagementAlgorithm_IsJudgedByTheProfile(string keyManagement, bool issued)
    {
        var issuer = Issuer();

        var issue = () => issuer.IssueAsync(
            Fapi1, Token(SigningAlgorithms.PS256), _signingKey, _encryptionKey, keyManagement);

        if (issued)
            Assert.Equal("issued", await issue());
        else
            await Assert.ThrowsAsync<AlgorithmRefusedByProfileException>(issue);
    }

    /// <summary>
    /// A refusal names what it refused, and for a key management algorithm the key it would have encrypted to, so a
    /// path that took the algorithm from a key a party published can tell that party's refusal from the server's.
    /// </summary>
    [Fact]
    public async Task ARefusal_NamesTheAlgorithmAndTheKey()
    {
        var issuer = Issuer();

        var keyManagement = await Assert.ThrowsAsync<AlgorithmRefusedByProfileException>(() => issuer.IssueAsync(
            Fapi1, Token(SigningAlgorithms.PS256), _signingKey, _encryptionKey,
            EncryptionAlgorithms.KeyManagement.Rsa1_5));
        var signing = await Assert.ThrowsAsync<AlgorithmRefusedByProfileException>(
            () => issuer.IssueAsync(Fapi1, Token(SigningAlgorithms.RS256), _signingKey));

        Assert.Equal(EncryptionAlgorithms.KeyManagement.Rsa1_5, keyManagement.Algorithm);
        Assert.Same(_encryptionKey, keyManagement.EncryptionKey);
        Assert.Equal(SigningAlgorithms.RS256, signing.Algorithm);
        Assert.Null(signing.EncryptionKey);
    }

    /// <summary>
    /// Nothing is issued against the profile: the creator is not reached.
    /// </summary>
    [Fact]
    public async Task ARefusal_NeverReachesTheCreator()
    {
        var issuer = Issuer();

        await Assert.ThrowsAsync<AlgorithmRefusedByProfileException>(
            () => issuer.IssueAsync(Fapi1, Token(SigningAlgorithms.RS256), _signingKey));

        _creator.Verify(
            c => c.IssueAsync(
                It.IsAny<JsonWebToken>(), It.IsAny<JsonWebKey?>(), It.IsAny<JsonWebKey?>(), It.IsAny<string>(),
                It.IsAny<string>()),
            Times.Never);
    }

    /// <summary>
    /// A tenant held to no profile is issued what it always was.
    /// </summary>
    [Fact]
    public async Task WithoutAProfile_EveryAlgorithmIsIssued()
    {
        var issuer = Issuer();

        Assert.Equal(
            "issued",
            await issuer.IssueAsync(
                Unprofiled,
                Token(SigningAlgorithms.RS256),
                _signingKey,
                _encryptionKey,
                EncryptionAlgorithms.KeyManagement.Rsa1_5));
    }
}
