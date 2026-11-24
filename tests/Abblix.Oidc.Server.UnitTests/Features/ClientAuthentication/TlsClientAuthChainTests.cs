// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Tests.Shared;
using Abblix.Utils;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// RFC 8705 section 2.1: tls_client_auth "relies on a validated certificate chain [RFC5280]", built against the
/// certificate authorities the tenant lists (section 7.4), whatever certificate the TLS layer let through.
/// </summary>
public class TlsClientAuthChainTests
{
    private const string ClientId = "pki-client";
    private const string SubjectDn = "CN=pki-client, O=Example Corp, C=US";

    private static readonly TestCertificateAuthority Authority = TestCertificateAuthority.Create();
    private static readonly TestCertificateAuthority OtherAuthority = TestCertificateAuthority.Create("CN=Other Root CA");
    private static readonly TestCertificateAuthority Layered = TestCertificateAuthority.CreateWithIntermediate("CN=Layered Root CA");

    private static TenantDefinition Trusting(params string[] authorities) => new()
    {
        Id = SingleIssuer.Tenant.Id,
        Issuer = SingleIssuer.Tenant.Issuer,
        TlsClientAuthCertificateAuthorities = authorities,
    };

    private static Task<Result<ClientInfo, OidcError>> AuthenticateAsync(
        TenantDefinition tenant, X509Certificate2 certificate)
    {
        var client = new ClientInfo(ClientId)
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            TlsClientAuth = new TlsClientAuthOptions { SubjectDn = SubjectDn },
        };
        var clients = new Mock<IClientInfoProvider>();
        clients.Setup(x => x.FindClientAsync(TestTenant.Matched, ClientId)).ReturnsAsync(client);

        var authenticator = new TlsMetadataClientAuthenticator(
            NullLogger<TlsMetadataClientAuthenticator>.Instance, TimeProvider.System);
        return authenticator.TryAuthenticateClientAsync(
            tenant,
            new ClientRequest { ClientId = ClientId, ClientCertificate = certificate },
            clients.Object);
    }

    /// <summary>
    /// A certificate the tenant's authority issued for the registered subject authenticates the client.
    /// </summary>
    [Fact]
    public async Task CertificateIssuedByTheTrustedAuthority_Authenticates()
    {
        using var certificate = Authority.Issue(SubjectDn);

        var result = await AuthenticateAsync(Trusting(Authority.RootEncoded), certificate);

        Assert.True(result.TryGetSuccess(out var client));
        Assert.Equal(ClientId, client.ClientId);
    }

    /// <summary>
    /// A certificate no listed authority issued authenticates no client, whatever subject it names.
    /// </summary>
    [Fact]
    public async Task ACertificateOfNoListedAuthority_IsRefused()
    {
        using var certificate = TestCertificateAuthority.SelfSigned(SubjectDn);

        var result = await AuthenticateAsync(Trusting(Authority.RootEncoded), certificate);

        Assert.Same(ClientAuthenticationFailures.InvalidCredential, result.GetFailure());
    }

    /// <summary>
    /// RFC 8705 section 7.4: an authority the tenant does not list vouches for no subject, the registered one included.
    /// </summary>
    [Fact]
    public async Task CertificateOfAnAuthorityTheTenantDoesNotList_IsRefused()
    {
        using var certificate = OtherAuthority.Issue(SubjectDn);

        var result = await AuthenticateAsync(Trusting(Authority.RootEncoded), certificate);

        Assert.Same(ClientAuthenticationFailures.InvalidCredential, result.GetFailure());
    }

    /// <summary>
    /// A tenant listing no certificate authority serves no tls_client_auth, so even a certificate a real authority
    /// issued authenticates a client stored with that method nowhere.
    /// </summary>
    [Fact]
    public async Task TenantListingNoAuthority_RefusesEveryCertificate()
    {
        using var certificate = Authority.Issue(SubjectDn);

        var result = await AuthenticateAsync(SingleIssuer.Tenant, certificate);

        Assert.Same(ClientAuthenticationFailures.InvalidCredential, result.GetFailure());
    }

    /// <summary>
    /// Only the client's own certificate reaches the server, so an intermediate authority is listed beside the root
    /// and the chain passes through it.
    /// </summary>
    [Fact]
    public async Task CertificateUnderAnIntermediateListedWithItsRoot_Authenticates()
    {
        using var certificate = Layered.Issue(SubjectDn);

        var result = await AuthenticateAsync(Trusting(Layered.RootEncoded, Layered.IntermediateEncoded), certificate);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Without the intermediate the chain cannot reach the root: nothing is downloaded from the addresses the
    /// certificate names.
    /// </summary>
    [Fact]
    public async Task CertificateUnderAnIntermediateNotListed_IsRefused()
    {
        using var certificate = Layered.Issue(SubjectDn);

        var result = await AuthenticateAsync(Trusting(Layered.RootEncoded), certificate);

        Assert.Same(ClientAuthenticationFailures.InvalidCredential, result.GetFailure());
    }

    /// <summary>
    /// The chain passes only through the authorities the tenant lists: an intermediate under a listed root that the
    /// chain engine finds elsewhere, as a certificate store of the host would supply it, does not carry it, while the
    /// same intermediate listed does.
    /// </summary>
    [Fact]
    public void AnIntermediateTheTenantDoesNotList_DoesNotCarryTheChain()
    {
        using var layered = TestCertificateAuthority.CreateWithIntermediate("CN=Found Root CA");
        using var certificate = layered.Issue(SubjectDn);
        using var intermediate = X509CertificateLoader.LoadCertificate(layered.Intermediate!.RawData);
        var now = TimeProvider.System.GetUtcNow();

        Assert.NotNull(TlsClientAuthCertificateAuthorities.WhyNotChained(
            Trusting(layered.RootEncoded), certificate, now, [intermediate]));
        Assert.Null(TlsClientAuthCertificateAuthorities.WhyNotChained(
            Trusting(layered.RootEncoded, layered.IntermediateEncoded), certificate, now, [intermediate]));
    }

    /// <summary>
    /// An intermediate listed alone is not a trust anchor, so a chain through it ends nowhere trusted.
    /// </summary>
    [Fact]
    public async Task IntermediateListedWithoutItsRoot_IsNoTrustAnchor()
    {
        using var certificate = Layered.Issue(SubjectDn);

        var result = await AuthenticateAsync(Trusting(Layered.IntermediateEncoded), certificate);

        Assert.Same(ClientAuthenticationFailures.InvalidCredential, result.GetFailure());
    }

    /// <summary>
    /// RFC 5280 section 6.1.3: a certificate is valid only within its validity period.
    /// </summary>
    [Fact]
    public async Task ExpiredCertificate_IsRefused()
    {
        var now = TimeProvider.System.GetUtcNow();
        using var certificate = Authority.Issue(SubjectDn, notBefore: now.AddDays(-2), notAfter: now.AddDays(-1));

        var result = await AuthenticateAsync(Trusting(Authority.RootEncoded), certificate);

        Assert.Same(ClientAuthenticationFailures.InvalidCredential, result.GetFailure());
    }

    /// <summary>
    /// RFC 5280 section 4.2.1.12: a certificate whose extended key usage names server authentication alone was not
    /// issued for a client.
    /// </summary>
    [Fact]
    public async Task CertificateIssuedForServerAuthenticationOnly_IsRefused()
    {
        using var certificate = Authority.Issue(SubjectDn, serverOnly: true);

        var result = await AuthenticateAsync(Trusting(Authority.RootEncoded), certificate);

        Assert.Same(ClientAuthenticationFailures.InvalidCredential, result.GetFailure());
    }

    /// <summary>
    /// A tenant's list of authorities is judged when the tenant enters the server: every entry a certificate
    /// authority's certificate, at least one of them a self-signed anchor.
    /// </summary>
    [Fact]
    public void AuthoritiesList_IsJudged()
    {
        using var leaf = Authority.Issue(SubjectDn);

        Assert.Empty(TlsClientAuthCertificateAuthorities.Refusals([]));
        Assert.Empty(TlsClientAuthCertificateAuthorities.Refusals([Authority.RootEncoded]));
        Assert.Empty(TlsClientAuthCertificateAuthorities.Refusals([Layered.RootEncoded, Layered.IntermediateEncoded]));
        Assert.Single(TlsClientAuthCertificateAuthorities.Refusals([Authority.RootEncoded, "not base64!"]));
        Assert.Single(TlsClientAuthCertificateAuthorities.Refusals(
            [Authority.RootEncoded, Convert.ToBase64String(leaf.RawData)]));
        Assert.Single(TlsClientAuthCertificateAuthorities.Refusals([Layered.IntermediateEncoded]));
    }

    /// <summary>
    /// The discovery document names tls_client_auth exactly where registration accepts it and a certificate the
    /// tenant's authority issued authenticates a client registered with it: RFC 8414 section 2 lists the methods
    /// "supported by this token endpoint".
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DiscoveryRegistrationAndAuthentication_AgreeOnTlsClientAuth(bool trustsAnAuthority)
    {
        var tenant = trustsAnAuthority ? Trusting(Authority.RootEncoded) : SingleIssuer.Tenant;
        var authenticator = new Mock<IClientAuthenticator>();
        authenticator.Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.TlsClientAuth]);

        var options = new Mock<IOptionsSnapshot<OidcOptions>>();
        options.Setup(o => o.Value).Returns(new OidcOptions());
        var document = await new ConfigurationHandler(
            options.Object,
            SingleIssuer.LicensedCatalog,
            Mock.Of<ILogoutNotifier>(),
            authenticator.Object,
            Mock.Of<IAuthorizationMetadataProvider>(),
            Mock.Of<IScopeClaimsProvider>(),
            Mock.Of<IScopesAndClaimsProvider>(),
            Mock.Of<IJwtAlgorithmsProvider>(),
            Mock.Of<IAuthServiceKeysProvider>(MockBehavior.Strict),
            [],
            Mock.Of<IAcrMetadataProvider>(),
            Mock.Of<IAuthorizationDetailsMetadataProvider>(),
            TestEncryptionAlgorithms.Every).HandleAsync(tenant);

        var registration = await new TokenEndpointAuthMethodValidator(authenticator.Object).ValidateAsync(
            tenant,
            new ClientRegistrationValidationContext(new ClientRegistrationRequest
            {
                RedirectUris = [TestConstants.DefaultRedirectUri],
                TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth,
            }));

        using var certificate = Authority.Issue(SubjectDn);
        var authenticated = await AuthenticateAsync(tenant, certificate);

        Assert.Equal(trustsAnAuthority, document.TokenEndpointAuthMethodsSupported is not null);
        Assert.Equal(trustsAnAuthority, registration is null);
        Assert.Equal(trustsAnAuthority, authenticated.TryGetSuccess(out _));
    }

    /// <summary>
    /// The tenant check refuses a tenant whose list cannot be served, naming the tenant.
    /// </summary>
    [Fact]
    public void TenantWithAnUnservableList_IsRefusedByTheTenantCheck()
    {
        var refusals = new TenantDefinitionsCheck()
            .Check([Trusting("not base64!")], new OidcOptions())
            .ToArray();

        Assert.Contains(refusals, refusal => refusal.TenantIds.Contains(SingleIssuer.Tenant.Id));
    }
}
