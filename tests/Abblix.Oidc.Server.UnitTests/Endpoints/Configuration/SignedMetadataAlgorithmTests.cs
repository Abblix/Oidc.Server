// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    private static async Task<string?> SignedWith(ClientSecurityProfile profile, JsonWebKey key)
    {
        string? algorithm = null;
        var creator = new Mock<IJsonWebTokenCreator>(MockBehavior.Strict);
        creator
            .Setup(c => c.IssueAsync(It.IsAny<JsonWebToken>(), key, null, It.IsAny<string>(), It.IsAny<string>()))
            .Callback<JsonWebToken, JsonWebKey, JsonWebKey?, string, string>((token, _, _, _, _) => algorithm = token.Header.Algorithm)
            .ReturnsAsync("signed");
        var keys = new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict);
        keys.Setup(k => k.GetSigningKeys(TestTenant.Matched, true)).Returns(() => new[] { key }.ToAsyncEnumerable());
        var tenant = new TestIssuer { DefaultSecurityProfile = profile }.ToTenant();

        await new SignedMetadataProvider(creator.Object, keys.Object, TimeProvider.System)
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
}
