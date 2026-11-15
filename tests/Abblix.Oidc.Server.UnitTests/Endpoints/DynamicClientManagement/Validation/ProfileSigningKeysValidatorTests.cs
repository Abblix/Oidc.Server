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
    /// The algorithms a registration names are judged only where the client can be issued what they sign, the answer
    /// startup gives: a client of the client credentials grant naming ES256 for its ID tokens and authorization
    /// responses at a tenant holding only an RSA key pinned to PS256 is accepted while it registers neither a response
    /// type nor a redirect URI, and refused once it registers a redirect URI, to which an error response is signed.
    /// </summary>
    [Theory]
    [InlineData(false, null)]
    [InlineData(true, ErrorCodes.InvalidClientMetadata)]
    public async Task AnAlgorithmForAJwtNeverIssued_IsNotJudged(bool redirectUri, string? expectedError)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = redirectUri ? [TestConstants.DefaultRedirectUri] : null,
            ResponseTypes = [],
            GrantTypes = [GrantTypes.ClientCredentials],
            IdTokenSignedResponseAlg = SigningAlgorithms.ES256,
            AuthorizationSignedResponseAlg = SigningAlgorithms.ES256,
        });

        var result = await Validator(Rsa(SigningAlgorithms.PS256))
            .ValidateAsync(Tenant(ClientSecurityProfile.Fapi2), context);

        Assert.Equal(expectedError, result?.Error);
    }

    /// <summary>
    /// A registration with no response type is judged for its ID token algorithm by its grant types: the CIBA grant and
    /// a grant the host defines are answered with an ID token at the token endpoint, so ES256 named for it at a tenant
    /// holding only an RSA key pinned to PS256 is refused, and the client credentials grant is issued none, so it is
    /// accepted.
    /// </summary>
    [Theory]
    [InlineData(GrantTypes.Ciba, ErrorCodes.InvalidClientMetadata)]
    [InlineData(HostDefinedGrantType, ErrorCodes.InvalidClientMetadata)]
    [InlineData(GrantTypes.ClientCredentials, null)]
    public async Task AnIdTokenAlgorithm_IsJudgedByTheGrantTypes(string grantType, string? expectedError)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            ResponseTypes = [],
            GrantTypes = [grantType],
            IdTokenSignedResponseAlg = SigningAlgorithms.ES256,
        });

        var result = await Validator(Rsa(SigningAlgorithms.PS256))
            .ValidateAsync(Tenant(ClientSecurityProfile.Fapi2), context);

        Assert.Equal(expectedError, result?.Error);
    }

    private const string HostDefinedGrantType = "urn:example:params:oauth:grant-type:host-defined";

    /// <summary>
    /// A registration of the client credentials grant naming a back-channel logout URI can still be sent a logout token,
    /// signed with the ID token's algorithm, so ES256 named for it at a tenant holding only an RSA key pinned to PS256
    /// is refused.
    /// </summary>
    [Fact]
    public async Task AnIdTokenAlgorithmSigningLogoutTokens_IsJudged()
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            BackChannelLogoutUri = TestConstants.DefaultRedirectUri,
            ResponseTypes = [],
            GrantTypes = [GrantTypes.ClientCredentials],
            IdTokenSignedResponseAlg = SigningAlgorithms.ES256,
        });

        var result = await Validator(Rsa(SigningAlgorithms.PS256))
            .ValidateAsync(Tenant(ClientSecurityProfile.Fapi2), context);

        Assert.Equal(ErrorCodes.InvalidClientMetadata, result?.Error);
    }

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

        // RFC 9701 section 6 would default an omitted introspection algorithm to RS256, which the profile refuses
        Assert.Equal(SigningAlgorithms.PS256, rsaTenant.Request.IntrospectionSignedResponseAlg);
        Assert.Equal(SigningAlgorithms.ES256, ecTenant.Request.IntrospectionSignedResponseAlg);
    }

    /// <summary>
    /// A registration naming its ID token and authorization algorithms but no introspection algorithm is given one for
    /// introspection too, and a named introspection algorithm is kept as named.
    /// </summary>
    [Theory]
    [InlineData(null, SigningAlgorithms.PS256)]
    [InlineData(SigningAlgorithms.ES256, SigningAlgorithms.ES256)]
    public async Task TheIntrospectionAlgorithm_IsGivenWhereUnnamed(string? named, string expected)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            IdTokenSignedResponseAlg = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlg = SigningAlgorithms.PS256,
            IntrospectionSignedResponseAlg = named,
        });

        Assert.Null(await Validator(Rsa(), Ec()).ValidateAsync(Tenant(ClientSecurityProfile.Fapi2MessageSigning), context));

        Assert.Equal(expected, context.Request.IntrospectionSignedResponseAlg);
    }

    /// <summary>
    /// OpenID Connect Core 1.0 section 5.3.2: a userinfo response registered for encryption is a JWT, which the profile
    /// refuses unsigned, so a registration naming userinfo encryption and no userinfo signature is given one; one
    /// naming no encryption is left as plain JSON, and a named signature is kept.
    /// </summary>
    [Theory]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, null, SigningAlgorithms.PS256)]
    [InlineData(null, null, null)]
    [InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, SigningAlgorithms.ES256, SigningAlgorithms.ES256)]
    public async Task TheUserInfoAlgorithm_IsGivenWhereEncryptedAndUnsigned(
        string? encryption, string? named, string? expected)
    {
        var context = new ClientRegistrationValidationContext(new ClientRegistrationRequest
        {
            RedirectUris = [TestConstants.DefaultRedirectUri],
            IdTokenSignedResponseAlg = SigningAlgorithms.PS256,
            AuthorizationSignedResponseAlg = SigningAlgorithms.PS256,
            IntrospectionSignedResponseAlg = SigningAlgorithms.PS256,
            UserInfoEncryptedResponseAlg = encryption,
            UserInfoSignedResponseAlg = named,
        });

        Assert.Null(await Validator(Rsa(), Ec()).ValidateAsync(Tenant(ClientSecurityProfile.Fapi1Advanced), context));

        Assert.Equal(expected, context.Request.UserInfoSignedResponseAlg);
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
