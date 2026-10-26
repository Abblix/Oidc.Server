// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
        scopesAndClaims.Setup(p => p.ScopesSupported(TestTenant.Matched)).Returns(["openid", "orders"]);
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
        Assert.Equal(["openid", "orders"], document.ScopesSupported);
        Assert.Equal(["sub", "order_id"], document.ClaimsSupported);
        Assert.Equal(["public", "pairwise"], document.SubjectTypesSupported);
        Assert.Equal(["urn:example:acr:strong"], document.AcrValuesSupported);
    }
}
