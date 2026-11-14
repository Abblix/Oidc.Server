// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Tokens.Formatters;
using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Configuration;

/// <summary>
/// The signed discovery document is a JWS this server creates, so at a tenant held to FAPI 1.0 Advanced it is signed
/// with an algorithm Part 2 section 8.6 names: PS256 with an RSA key declaring no algorithm, where a tenant held to no
/// profile keeps RS256; a key declaring RS256 alone leaves nothing the profile admits, and the document is not signed.
/// </summary>
public class SignedMetadataAlgorithmTests
{
    private static Task<string?> SignedWith(ClientSecurityProfile profile, JsonWebKey key)
        => SignedWith(profile, key, key);

    private static async Task<string?> SignedWith(ClientSecurityProfile profile, JsonWebKey used, params JsonWebKey[] all)
    {
        var key = used;
        string? algorithm = null;
        var creator = new Mock<IJsonWebTokenCreator>(MockBehavior.Strict);
        creator
            .Setup(c => c.IssueAsync(It.IsAny<JsonWebToken>(), key, null, It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((token, _, _, _, _) => algorithm = token.Header.Algorithm)
            .ReturnsAsync("signed");
        var keys = new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict);
        keys.Setup(k => k.GetSigningKeys(TestTenant.Matched, true)).Returns(() => all.ToAsyncEnumerable());
        var tenant = new TestIssuer { DefaultSecurityProfile = profile }.ToTenant();

        await new SignedMetadataProvider(new ProfiledJwtIssuer(creator.Object), keys.Object, TimeProvider.System)
            .SignAsync(tenant, new Abblix.Oidc.Server.Model.ConfigurationResponse
            {
                Issuer = tenant.Issuer.OriginalString,
                IdTokenSigningAlgValuesSupported = [SigningAlgorithms.PS256],
                ResponseTypesSupported = [ResponseTypes.Code],
                SubjectTypesSupported = [SubjectTypes.Public],
            });

        return algorithm;
    }

    [Fact]
    public async Task AnRsaKeyDeclaringNoAlgorithm_SignsPs256UnderFapi1Advanced()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        key.Algorithm = null;

        Assert.Equal(SigningAlgorithms.PS256, await SignedWith(ClientSecurityProfile.Fapi1Advanced, key));
        Assert.Equal(SigningAlgorithms.RS256, await SignedWith(ClientSecurityProfile.None, key));
    }

    [Fact]
    public async Task AKeyDeclaringRs256Alone_IsNotUsedUnderFapi1Advanced()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

        await Assert.ThrowsAsync<InvalidOperationException>(() => SignedWith(ClientSecurityProfile.Fapi1Advanced, key));
    }

    /// <summary>
    /// A key whose algorithm cannot be named - a curve this server has no algorithm for, and no alg declared - is
    /// passed over at a FAPI tenant rather than ending the walk, so a later key the profile admits signs.
    /// </summary>
    [Fact]
    public async Task AKeyWithoutANameableAlgorithm_IsPassedOverUnderFapi1Advanced()
    {
        var rs256 = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var unnamed = new EllipticCurveJsonWebKey { KeyId = "unnamed", Curve = "secp256k1" };
        var ps256 = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.PS256);

        Assert.Equal(
            SigningAlgorithms.PS256,
            await SignedWith(ClientSecurityProfile.Fapi1Advanced, ps256, rs256, unnamed, ps256));
    }
}
