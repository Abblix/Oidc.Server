// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Validation;

/// <summary>
/// The one door to <see cref="IJsonWebTokenValidator"/> for what this server accepts: it stamps the validation with the
/// algorithms the profile in force admits, on top of whatever the caller asks for itself. FAPI 1.0 Part 2 section 8.6:
/// "For JWS, both clients and authorization servers shall use PS256 or ES256 algorithms"; section 8.6.1: "For JWE ...
/// shall not use the RSA1_5 algorithm"; FAPI 2.0 section 5.4.1, "when creating or processing JWTs".
/// </summary>
public class ProfiledJwtValidatorTests
{
    private const string Jwt = "header.payload.signature";

    private static readonly SecurityProfileRequirements Fapi1 =
        SecurityProfileRequirements.Resolve(ClientSecurityProfile.Fapi1Advanced);

    private static readonly SecurityProfileRequirements Unprofiled =
        SecurityProfileRequirements.Resolve(ClientSecurityProfile.None);

    private readonly Mock<IJsonWebTokenValidator> _validator = new(MockBehavior.Strict);

    private ValidationParameters? _seen;

    private ProfiledJwtValidator Guard()
    {
        _validator
            .Setup(v => v.ValidateAsync(Jwt, It.IsAny<ValidationParameters>()))
            .Callback<string, ValidationParameters>((_, parameters) => _seen = parameters)
            .ReturnsAsync(new JsonWebToken());
        return new ProfiledJwtValidator(_validator.Object);
    }

    private static ValidationParameters Parameters(
        IReadOnlySet<string>? allowed = null,
        System.Func<string, bool>? keyManagement = null)
        => new()
        {
            TokenTypes = TokenTypePolicy.CheckedByCaller,
            AllowedSigningAlgorithms = allowed,
            ValidateKeyManagementAlgorithm = keyManagement,
        };

    [Fact]
    public async Task TheProfilesAlgorithms_AreStamped()
    {
        await Guard().ValidateAsync(Fapi1, Jwt, Parameters());

        Assert.Equal([SigningAlgorithms.ES256, SigningAlgorithms.PS256], _seen!.AllowedSigningAlgorithms!.Order());
        Assert.False(_seen.ValidateKeyManagementAlgorithm!(EncryptionAlgorithms.KeyManagement.Rsa1_5));
        Assert.True(_seen.ValidateKeyManagementAlgorithm(EncryptionAlgorithms.KeyManagement.RsaOaep256));
    }

    /// <summary>
    /// A caller's own list is narrowed to what the profile also admits, as DPoP's asymmetric-only list is.
    /// </summary>
    [Fact]
    public async Task ACallersList_IsIntersectedWithTheProfiles()
    {
        await Guard().ValidateAsync(
            Fapi1, Jwt, Parameters(new HashSet<string> { SigningAlgorithms.RS256, SigningAlgorithms.ES256 }));

        Assert.Equal([SigningAlgorithms.ES256], _seen!.AllowedSigningAlgorithms!.ToArray());
    }

    /// <summary>
    /// Where the two lists share nothing the token is refused without being read, since an empty list is what the
    /// validator takes for no list at all.
    /// </summary>
    [Fact]
    public async Task ListsSharingNothing_RefuseWithoutValidating()
    {
        var result = await Guard().ValidateAsync(Fapi1, Jwt, Parameters(new HashSet<string> { SigningAlgorithms.RS256 }));

        Assert.True(result.TryGetFailure(out _));
        _validator.Verify(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()), Times.Never);
    }

    /// <summary>
    /// A caller's own judgement of a key management algorithm still runs, and both have to admit it.
    /// </summary>
    [Fact]
    public async Task ACallersKeyManagementJudgement_IsKeptBesideTheProfiles()
    {
        var asked = new List<string>();

        await Guard().ValidateAsync(Fapi1, Jwt, Parameters(keyManagement: algorithm =>
        {
            asked.Add(algorithm);
            return algorithm != EncryptionAlgorithms.KeyManagement.RsaOaep;
        }));

        Assert.False(_seen!.ValidateKeyManagementAlgorithm!(EncryptionAlgorithms.KeyManagement.RsaOaep));
        Assert.False(_seen.ValidateKeyManagementAlgorithm(EncryptionAlgorithms.KeyManagement.Rsa1_5));
        Assert.True(_seen.ValidateKeyManagementAlgorithm(EncryptionAlgorithms.KeyManagement.RsaOaep256));
        Assert.Equal(3, asked.Count);
    }

    /// <summary>
    /// A tenant held to no profile is validated as the caller asked.
    /// </summary>
    [Fact]
    public async Task WithoutAProfile_TheCallersParametersStand()
    {
        await Guard().ValidateAsync(Unprofiled, Jwt, Parameters());

        Assert.Null(_seen!.AllowedSigningAlgorithms);
        Assert.True(_seen.ValidateKeyManagementAlgorithm?.Invoke(EncryptionAlgorithms.KeyManagement.Rsa1_5) ?? true);
    }
}
