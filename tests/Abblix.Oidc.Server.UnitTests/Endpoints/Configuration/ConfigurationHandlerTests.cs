// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Jwt;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Configuration;

/// <summary>
/// Covers <see cref="ConfigurationHandler"/>: the discovery document describes the tenant it is built for.
/// </summary>
public class ConfigurationHandlerTests
{
    /// <summary>
    /// The scopes, claims and subject types the document lists are those of the tenant the request is served at:
    /// the provider answers them for that tenant alone.
    /// </summary>
    [Fact]
    public async Task TheDocument_ListsTheScopesClaimsAndSubjectTypesOfTheTenantItIsBuiltFor()
    {
        var scopesAndClaims = new Mock<IScopesAndClaimsProvider>();
        scopesAndClaims.Setup(p => p.ScopesSupported(TestTenant.Matched)).Returns([Scopes.OpenId, "orders"]);
        scopesAndClaims.Setup(p => p.ClaimsSupported(TestTenant.Matched)).Returns(["sub", "order_id"]);
        scopesAndClaims.Setup(p => p.SubjectTypesSupported(TestTenant.Matched)).Returns(["public", "pairwise"]);
        var acr = new Mock<IAcrMetadataProvider>();
        acr.Setup(p => p.AcrValuesSupported(TestTenant.Matched)).Returns(["urn:example:acr:strong"]);

        var options = new Mock<IOptionsSnapshot<OidcOptions>>();
        options.Setup(o => o.Value).Returns(new OidcOptions());
        var clientAuthenticator = new Mock<IClientAuthenticator>();
        clientAuthenticator.Setup(a => a.ClientAuthenticationMethodsSupported).Returns([]);

        var handler = new ConfigurationHandler(
            options.Object,
            SingleIssuer.LicensedCatalog,
            Mock.Of<ILogoutNotifier>(),
            clientAuthenticator.Object,
            Mock.Of<IAuthorizationMetadataProvider>(),
            scopesAndClaims.Object,
            Mock.Of<IJwtAlgorithmsProvider>(),
            [],
            acr.Object,
            Mock.Of<IAuthorizationDetailsMetadataProvider>());

        var document = await handler.HandleAsync(SingleIssuer.Tenant);

        Assert.Equal(SingleIssuer.Tenant.Issuer, document.Issuer);
        Assert.Equal([Scopes.OpenId, "orders"], document.ScopesSupported);
        Assert.Equal(["sub", "order_id"], document.ClaimsSupported);
        Assert.Equal(["public", "pairwise"], document.SubjectTypesSupported);
        Assert.Equal(["urn:example:acr:strong"], document.AcrValuesSupported);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 sections 8.6 and 8.6.1: a tenant held to FAPI 1.0 Advanced advertises only PS256 and ES256 in
    /// every signing list, DPoP's included, and no RSA1_5 among the key management algorithms; a userinfo or
    /// introspection response may still be plain JSON. A tenant held to no profile advertises what the server
    /// supports.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, true)]
    [InlineData(ClientSecurityProfile.None, false)]
    public async Task TheDocument_AdvertisesWhatTheTenantsProfileAdmits(ClientSecurityProfile profile, bool narrowed)
    {
        string[] signing = [SigningAlgorithms.RS256, SigningAlgorithms.PS256, SigningAlgorithms.ES256];
        string[] keyManagement = [EncryptionAlgorithms.KeyManagement.Rsa1_5, EncryptionAlgorithms.KeyManagement.RsaOaep256];
        var algorithms = new Mock<IJwtAlgorithmsProvider>();
        algorithms.Setup(a => a.SignedResponseAlgorithmsSupported).Returns([SigningAlgorithms.None, ..signing]);
        algorithms.Setup(a => a.SigningAlgorithmsSupported).Returns(signing);
        algorithms.Setup(a => a.TokenEndpointAuthSigningAlgValuesSupported).Returns(signing);
        algorithms.Setup(a => a.DpopSigningAlgorithmsSupported).Returns(signing);
        algorithms.Setup(a => a.AuthorizationSigningAlgValuesSupported).Returns(signing);
        algorithms.Setup(a => a.IntrospectionSigningAlgValuesSupported).Returns(signing);
        algorithms.Setup(a => a.RequestObjectEncryptionAlgValuesSupported).Returns(keyManagement);
        algorithms.Setup(a => a.AuthorizationEncryptionAlgValuesSupported).Returns(keyManagement);
        algorithms.Setup(a => a.IntrospectionEncryptionAlgValuesSupported).Returns(keyManagement);
        var metadata = new Mock<IAuthorizationMetadataProvider>();
        metadata.Setup(m => m.RequestParameterSupported).Returns(true);
        var options = new Mock<IOptionsSnapshot<OidcOptions>>();
        options.Setup(o => o.Value).Returns(new OidcOptions());
        var clientAuthenticator = new Mock<IClientAuthenticator>();
        clientAuthenticator.Setup(a => a.ClientAuthenticationMethodsSupported).Returns([]);
        var handler = new ConfigurationHandler(
            options.Object,
            SingleIssuer.LicensedCatalog,
            Mock.Of<ILogoutNotifier>(),
            clientAuthenticator.Object,
            metadata.Object,
            Mock.Of<IScopesAndClaimsProvider>(),
            algorithms.Object,
            [],
            Mock.Of<IAcrMetadataProvider>(),
            Mock.Of<IAuthorizationDetailsMetadataProvider>());

        var document = await handler.HandleAsync(new TestIssuer { DefaultSecurityProfile = profile }.ToTenant());

        string[] admitted = narrowed ? [SigningAlgorithms.PS256, SigningAlgorithms.ES256] : signing;
        string[] encryption = narrowed ? [EncryptionAlgorithms.KeyManagement.RsaOaep256] : keyManagement;
        // An unsigned ID token is one no profile admits
        Assert.Equal(narrowed ? admitted : [SigningAlgorithms.None, ..signing], document.IdTokenSigningAlgValuesSupported);
        Assert.Equal(admitted, document.RequestObjectSigningAlgValuesSupported);
        Assert.Equal(admitted, document.TokenEndpointAuthSigningAlgValuesSupported);
        Assert.Equal(admitted, document.DpopSigningAlgValuesSupported);
        Assert.Equal(admitted, document.AuthorizationSigningAlgValuesSupported);
        Assert.Equal([SigningAlgorithms.None, ..admitted], document.UserInfoSigningAlgValuesSupported);
        Assert.Equal(encryption, document.RequestObjectEncryptionAlgValuesSupported);
        Assert.Equal(encryption, document.AuthorizationEncryptionAlgValuesSupported);
        Assert.Equal(encryption, document.IntrospectionEncryptionAlgValuesSupported);
    }
}
