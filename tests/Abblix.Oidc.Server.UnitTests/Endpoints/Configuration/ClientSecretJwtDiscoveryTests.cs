// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Configuration;

/// <summary>
/// The discovery document names an HS algorithm for client_secret_jwt only where a secret of the length the server
/// generates keys it (RFC 7518 section 3.2), since the client's assertion is verified with no other key.
/// </summary>
public class ClientSecretJwtDiscoveryTests
{
    [Theory]
    [InlineData(32, new[] { SigningAlgorithms.RS256, SigningAlgorithms.HS256 })]
    [InlineData(48, new[] { SigningAlgorithms.RS256, SigningAlgorithms.HS256, SigningAlgorithms.HS384 })]
    [InlineData(64, new[] { SigningAlgorithms.RS256, SigningAlgorithms.HS256, SigningAlgorithms.HS384, SigningAlgorithms.HS512 })]
    public async Task TheDocumentNamesTheHsAlgorithmsAnIssuedSecretKeys(int secretLength, string[] listed)
    {
        var algorithms = new Mock<IJwtAlgorithmsProvider>();
        algorithms.Setup(a => a.TokenEndpointAuthSigningAlgValuesSupported).Returns(
            [SigningAlgorithms.RS256, SigningAlgorithms.HS256, SigningAlgorithms.HS384, SigningAlgorithms.HS512]);
        var options = new Mock<IOptionsSnapshot<OidcOptions>>();
        options.Setup(o => o.Value).Returns(new OidcOptions
        {
            NewClientOptions = new NewClientOptions { ClientSecret = new ClientSecretOptions { Length = secretLength } },
        });
        var authenticator = new Mock<IClientAuthenticator>();
        authenticator.Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.ClientSecretJwt]);

        var document = await new ConfigurationHandler(
            options.Object,
            SingleIssuer.LicensedCatalog,
            Mock.Of<ILogoutNotifier>(),
            authenticator.Object,
            Mock.Of<IAuthorizationMetadataProvider>(),
            Mock.Of<IScopeClaimsProvider>(),
            Mock.Of<IScopesAndClaimsProvider>(),
            algorithms.Object,
            Mock.Of<IAuthServiceKeysProvider>(MockBehavior.Strict),
            [],
            Mock.Of<IAcrMetadataProvider>(),
            Mock.Of<IAuthorizationDetailsMetadataProvider>(),
            TestEncryptionAlgorithms.Every).HandleAsync(SingleIssuer.Tenant);

        Assert.Equal(listed, document.TokenEndpointAuthSigningAlgValuesSupported);
    }
}
