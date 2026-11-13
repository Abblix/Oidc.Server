// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement.Validation;

/// <summary>
/// A registration under a profile admitting only PS256 and ES256 (FAPI 1.0 Part 2 section 8.6, FAPI 2.0 section
/// 5.4.1) is given, for what the server signs for it and it named nothing for, an algorithm one of the tenant's signing
/// keys can produce, and is refused when none can, rather than registered and failing at its first ID token.
/// </summary>
public class ProfileSigningKeysValidatorTests
{
    private static TenantDefinition Tenant(ClientSecurityProfile profile)
        => new TestIssuer { DefaultSecurityProfile = profile }.ToTenant();

    private static ProfileSigningKeysValidator Validator(params JsonWebKey[] signingKeys)
    {
        var keys = new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict);
        keys.Setup(k => k.GetSigningKeys(TestTenant.Matched, It.IsAny<bool>()))
            .Returns(() => signingKeys.ToAsyncEnumerable());
        return new ProfileSigningKeysValidator(keys.Object);
    }

    private static ClientRegistrationValidationContext Context(string? idTokenAlgorithm = null)
        => new(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            IdTokenSignedResponseAlg = idTokenAlgorithm,
        });

    private static RsaJsonWebKey Rsa(string? algorithm = null)
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        key.Algorithm = algorithm;
        return key;
    }

    private static EllipticCurveJsonWebKey Ec()
        => JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256);

    /// <summary>
    /// The algorithm given is the first of PS256 and ES256 a key of the tenant can produce: PS256 with an RSA key
    /// declaring no algorithm, ES256 with a P-256 key alone.
    /// </summary>
    [Fact]
    public async Task AnUnnamedAlgorithm_IsOneATenantKeyCanProduce()
    {
        var rsaTenant = Context();
        var ecTenant = Context();

        Assert.Null(await Validator(Rsa()).ValidateAsync(Tenant(ClientSecurityProfile.Fapi1Advanced), rsaTenant));
        Assert.Null(await Validator(Ec()).ValidateAsync(Tenant(ClientSecurityProfile.Fapi1Advanced), ecTenant));

        Assert.Equal(SigningAlgorithms.PS256, rsaTenant.Request.IdTokenSignedResponseAlg);
        Assert.Equal(SigningAlgorithms.PS256, rsaTenant.Request.AuthorizationSignedResponseAlg);
        Assert.Equal(SigningAlgorithms.ES256, ecTenant.Request.IdTokenSignedResponseAlg);
        Assert.Equal(SigningAlgorithms.ES256, ecTenant.Request.AuthorizationSignedResponseAlg);
    }

    /// <summary>
    /// A tenant whose only key declares RS256 can produce neither, so the registration is refused with
    /// invalid_client_metadata instead of accepted and failing with a 500 when the first ID token is signed.
    /// </summary>
    [Fact]
    public async Task NoTenantKeyProducingAPermittedAlgorithm_RefusesTheRegistration()
    {
        var result = await Validator(Rsa(SigningAlgorithms.RS256))
            .ValidateAsync(Tenant(ClientSecurityProfile.Fapi1Advanced), Context());

        Assert.Equal(ErrorCodes.InvalidClientMetadata, result?.Error);
    }

    /// <summary>
    /// A named algorithm no tenant key can produce is refused as well: PS256 at a tenant holding only a P-256 key.
    /// </summary>
    [Fact]
    public async Task ANamedAlgorithmNoTenantKeyProduces_RefusesTheRegistration()
    {
        var result = await Validator(Ec())
            .ValidateAsync(Tenant(ClientSecurityProfile.Fapi1Advanced), Context(SigningAlgorithms.PS256));

        Assert.Equal(ErrorCodes.InvalidClientMetadata, result?.Error);
    }

    /// <summary>
    /// Without a profile bounding the algorithms the registration is left as it came, its unnamed algorithms to the
    /// RS256 default OpenID Connect Dynamic Client Registration section 2 names.
    /// </summary>
    [Fact]
    public async Task WithoutAProfile_TheRegistrationIsLeftAsItCame()
    {
        var context = Context();

        Assert.Null(await Validator(Ec()).ValidateAsync(Tenant(ClientSecurityProfile.None), context));
        Assert.Null(context.Request.IdTokenSignedResponseAlg);
    }
}
