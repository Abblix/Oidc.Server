// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Tests.Shared;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// A tenant whose security profile admits none of the client authentication methods the server offers it at the token
/// endpoint is refused, the refusal naming it alone, and a tenant admitting one is let through; the methods discovery lists for the
/// tenant are the ones the check finds admitted.
/// </summary>
public class TenantAuthenticationMethodsCheckTests
{
    private const string SharedSecretsAndNone = "shared secrets and none";
    private const string TlsAlone = "tls_client_auth alone";
    private const string KeyBased = "private_key_jwt and shared secrets";
    private const string Nothing = "nothing";

    private static string[] Offered(string offer) => offer switch
    {
        SharedSecretsAndNone =>
        [
            ClientAuthenticationMethods.None,
            ClientAuthenticationMethods.ClientSecretBasic,
            ClientAuthenticationMethods.ClientSecretPost,
            ClientAuthenticationMethods.ClientSecretJwt,
        ],
        TlsAlone => [ClientAuthenticationMethods.TlsClientAuth],
        KeyBased => [ClientAuthenticationMethods.ClientSecretBasic, ClientAuthenticationMethods.PrivateKeyJwt],
        Nothing => [],
        _ => throw new System.ArgumentOutOfRangeException(nameof(offer), offer, null),
    };

    public static TheoryData<ClientSecurityProfile, string, bool, bool> Cases => new()
    {
        { ClientSecurityProfile.None, SharedSecretsAndNone, false, false },
        { ClientSecurityProfile.None, TlsAlone, false, true },
        { ClientSecurityProfile.None, TlsAlone, true, false },
        { ClientSecurityProfile.None, Nothing, false, true },
        { ClientSecurityProfile.Fapi2, SharedSecretsAndNone, false, true },
        { ClientSecurityProfile.Fapi1Advanced, SharedSecretsAndNone, false, true },
        { ClientSecurityProfile.Fapi2, KeyBased, false, false },
        { ClientSecurityProfile.Fapi2, TlsAlone, false, true },
        { ClientSecurityProfile.Fapi2, TlsAlone, true, false },
        { (ClientSecurityProfile)int.MaxValue, SharedSecretsAndNone, false, true },
        { (ClientSecurityProfile)int.MaxValue, KeyBased, false, false },
    };

    /// <summary>
    /// The tenant is refused exactly where its profile, with the certificate authorities it lists for tls_client_auth,
    /// admits no method the server offers; a refusal names the tenant alone.
    /// </summary>
    [Theory]
    [MemberData(nameof(Cases))]
    public void ATenant_IsRefused_WhereItAdmitsNoOfferedMethod(
        ClientSecurityProfile profile,
        string offer,
        bool listsAuthority,
        bool refused)
    {
        using var authority = TestCertificateAuthority.Create();
        var tenant = TenantOf(profile, listsAuthority ? authority : null);

        var refusals = CheckOver(Offered(offer)).Check([tenant], new OidcOptions()).ToArray();

        if (refused)
            Assert.Equal([TestIssuer.TenantId], Assert.Single(refusals).TenantIds);
        else
            Assert.Empty(refusals);
    }

    /// <summary>
    /// Discovery lists for the tenant's token endpoint exactly the methods the check finds the tenant admits, and lists
    /// none where the check refuses the tenant: both ask one owner which methods a tenant admits.
    /// </summary>
    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Discovery_ListsTheMethodsTheCheckAdmits(
        ClientSecurityProfile profile,
        string offer,
        bool listsAuthority,
        bool refused)
    {
        using var authority = TestCertificateAuthority.Create();
        var tenant = TenantOf(profile, listsAuthority ? authority : null);
        var offered = Offered(offer);

        var document = await HandlerOver(offered).HandleAsync(tenant);
        var refusals = CheckOver(offered).Check([tenant], new OidcOptions());

        Assert.Equal(refused, refusals.Any());
        Assert.Equal(refused, document.TokenEndpointAuthMethodsSupported is null);
        if (!refused)
            Assert.Equal(TenantClientAuthenticationMethods.Admitted(tenant, offered), document.TokenEndpointAuthMethodsSupported);
    }

    private static TenantDefinition TenantOf(ClientSecurityProfile profile, TestCertificateAuthority? authority)
        => new TestIssuer
        {
            DefaultSecurityProfile = profile,
            TlsClientAuthCertificateAuthorities = authority is null ? [] : [authority.RootEncoded],
        }.ToTenant();

    private static TenantAuthenticationMethodsCheck CheckOver(string[] offered)
        => new(new ServiceCollection().AddSingleton(AuthenticatorOffering(offered)).BuildServiceProvider());

    private static IClientAuthenticator AuthenticatorOffering(string[] offered)
    {
        var authenticator = new Mock<IClientAuthenticator>();
        authenticator.Setup(a => a.ClientAuthenticationMethodsSupported).Returns(offered);
        return authenticator.Object;
    }

    private static ConfigurationHandler HandlerOver(string[] offered)
    {
        var options = new Mock<IOptionsSnapshot<OidcOptions>>();
        options.Setup(o => o.Value).Returns(new OidcOptions());
        return new ConfigurationHandler(
            options.Object,
            SingleIssuer.LicensedCatalog,
            Mock.Of<ILogoutNotifier>(),
            AuthenticatorOffering(offered),
            Mock.Of<IAuthorizationMetadataProvider>(),
            Mock.Of<IScopeClaimsProvider>(),
            Mock.Of<IScopesAndClaimsProvider>(),
            Mock.Of<IJwtAlgorithmsProvider>(),
            Mock.Of<IAuthServiceKeysProvider>(MockBehavior.Strict),
            [],
            Mock.Of<IAcrMetadataProvider>(),
            Mock.Of<IAuthorizationDetailsMetadataProvider>(),
            TestEncryptionAlgorithms.Every);
    }
}
