// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ResponseObject;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ResponseObject;

/// <summary>
/// The algorithm an RFC 9701 introspection response is signed with: the client's own, or where it registered none,
/// the default the specification names, held to the security profile the client is under.
/// </summary>
public class IntrospectionResponseJwtBuilderTests
{
    private JsonWebToken? _signed;

    private IntrospectionResponseJwtBuilder Builder(params JsonWebKey[] signingKeys)
    {
        var formatter = new Mock<IClientJwtFormatter>(MockBehavior.Strict);
        formatter
            .Setup(f => f.FormatAsync(
                It.IsAny<TenantDefinition>(), It.IsAny<JsonWebToken>(), It.IsAny<ClientInfo>(), It.IsAny<ClientJwtEncryption>()))
            .Callback<TenantDefinition, JsonWebToken, ClientInfo, ClientJwtEncryption>((_, token, _, _) => _signed = token)
            .ReturnsAsync("header.payload.signature");

        var keys = new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict);
        keys.Setup(k => k.GetSigningKeys(It.IsAny<TenantDefinition>(), It.IsAny<bool>()))
            .Returns(() => signingKeys.ToAsyncEnumerable());

        return new IntrospectionResponseJwtBuilder(
            formatter.Object, TimeProvider.System, Options.Create(new OidcOptions()), keys.Object);
    }

    private static TenantDefinition Tenant(ClientSecurityProfile profile)
        => new TestIssuer { DefaultSecurityProfile = profile }.ToTenant();

    private static ClientInfo Client(string algorithm = SigningAlgorithms.None)
        => new(TestConstants.DefaultClientId) { IntrospectionSignedResponseAlgorithm = algorithm };

    private static EllipticCurveJsonWebKey Ec()
        => JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256);

    /// <summary>
    /// RFC 9701 section 6, introspection_signed_response_alg: "The default, if omitted, is RS256". A registered
    /// algorithm is used as registered.
    /// </summary>
    [Theory]
    [InlineData(SigningAlgorithms.None, SigningAlgorithms.RS256)]
    [InlineData(SigningAlgorithms.ES384, SigningAlgorithms.ES384)]
    public async Task WithoutAProfile_TheClientsAlgorithmOrRs256(string registered, string expected)
    {
        await Builder(
                JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature),
                JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P384, SigningAlgorithms.ES384))
            .BuildAsync(Tenant(ClientSecurityProfile.None), Client(registered), new JsonObject());

        Assert.Equal(expected, _signed?.Header.Algorithm);
    }

    /// <summary>
    /// Without a profile the default is RS256 alone: a tenant whose keys cannot produce it, holding a P-256 key, signs
    /// with nothing else and answers that the JWT is not available.
    /// </summary>
    [Fact]
    public async Task WithoutAProfile_ATenantWithoutAnRsaKey_IsNotAcceptable()
    {
        var result = await Builder(Ec()).BuildAsync(Tenant(ClientSecurityProfile.None), Client(), new JsonObject());

        Assert.True(result.TryGetFailure(out var error));
        Assert.IsType<NotAcceptableError>(error);
        Assert.Null(_signed);
    }

    /// <summary>
    /// Under a profile, a tenant whose keys produce none of the algorithms it admits answers the same way.
    /// </summary>
    [Fact]
    public async Task UnderAFapiProfile_ATenantWithoutAKeyForAnAdmittedAlgorithm_IsNotAcceptable()
    {
        var result = await Builder(JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P384, SigningAlgorithms.ES384))
            .BuildAsync(Tenant(ClientSecurityProfile.Fapi2), Client(), new JsonObject());

        Assert.True(result.TryGetFailure(out var error));
        Assert.IsType<NotAcceptableError>(error);
    }

    /// <summary>
    /// A profile admitting only PS256 and ES256 (FAPI 2.0 section 5.4.1) would refuse the default, so a client naming
    /// none is signed for with the first of them a key of the tenant produces: PS256 with an RSA key, ES256 with a
    /// P-256 key alone.
    /// </summary>
    [Theory]
    [InlineData(true, SigningAlgorithms.PS256)]
    [InlineData(false, SigningAlgorithms.ES256)]
    public async Task UnderAFapiProfile_TheFirstAdmittedAlgorithmAKeyProduces(bool rsa, string expected)
    {
        JsonWebKey key = rsa ? JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature) : Ec();

        await Builder(key).BuildAsync(Tenant(ClientSecurityProfile.Fapi2MessageSigning), Client(), new JsonObject());

        Assert.Equal(expected, _signed?.Header.Algorithm);
    }

    /// <summary>
    /// The JWT carries what RFC 9701 section 5 has it carry: the introspection type, the issuer, the resource server
    /// as audience, the issue time and the response under token_introspection, and no exp, which it SHOULD NOT.
    /// </summary>
    [Fact]
    public async Task TheJwt_CarriesWhatSection5Requires()
    {
        var tenant = Tenant(ClientSecurityProfile.None);

        await Builder(JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature))
            .BuildAsync(tenant, Client(), new JsonObject { [IntrospectionSuccess.Parameters.Active] = true });

        Assert.NotNull(_signed);
        Assert.Equal(JsonWebTokenTypes.TokenIntrospection, _signed.Header.Type);
        Assert.Equal(tenant.Issuer.OriginalString, _signed.Payload.Issuer);
        Assert.Equal([TestConstants.DefaultClientId], _signed.Payload.Audiences);
        Assert.NotNull(_signed.Payload.IssuedAt);
        Assert.Null(_signed.Payload.ExpiresAt);
        Assert.True(_signed.Payload[IanaClaimTypes.TokenIntrospection]![IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
    }
}
