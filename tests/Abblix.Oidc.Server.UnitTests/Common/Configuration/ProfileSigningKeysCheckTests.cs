// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common.Configuration;

/// <summary>
/// A tenant declaring a client its profile holds to PS256 or ES256 has a signing key that produces the algorithm the
/// client is configured for, or is refused at startup instead of failing when the first ID token is signed.
/// </summary>
public class ProfileSigningKeysCheckTests
{
    private static ClientInfo Client(string algorithm) => new(TestConstants.DefaultClientId)
    {
        TokenEndpointAuthMethod = ClientAuthenticationMethods.PrivateKeyJwt,
        IdentityTokenSignedResponseAlgorithm = algorithm,
        AuthorizationSignedResponseAlgorithm = algorithm,
    };

    private static TenantDefinition Tenant(JsonWebKey key, ClientInfo client) => new TestIssuer
    {
        DefaultSecurityProfile = ClientSecurityProfile.Fapi1Advanced,
        SigningKeys = [key],
        Clients = [client],
    }.ToTenant();

    private static EllipticCurveJsonWebKey Ec()
        => JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256);

    /// <summary>
    /// A client configured for PS256 at a tenant holding only a P-256 key is refused; the same client configured for
    /// ES256 is not, and neither is one configured for PS256 at a tenant holding an RSA key.
    /// </summary>
    [Fact]
    public void AClientConfiguredForAnAlgorithmNoKeyProduces_IsRefused()
    {
        var check = new ProfileSigningKeysCheck();
        var options = new OidcOptions();

        Assert.NotEmpty(check.Check([Tenant(Ec(), Client(SigningAlgorithms.PS256))], options).ToList());
        Assert.Empty(check.Check([Tenant(Ec(), Client(SigningAlgorithms.ES256))], options).ToList());
        Assert.Empty(check.Check(
            [Tenant(JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature), Client(SigningAlgorithms.PS256))],
            options).ToList());
    }
}
