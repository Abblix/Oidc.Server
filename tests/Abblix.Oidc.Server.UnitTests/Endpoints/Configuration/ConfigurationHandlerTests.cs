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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
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
            Mock.Of<IAuthServiceKeysProvider>(MockBehavior.Strict),
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
        // A key declaring no algorithm, whose material performs every RSA key management algorithm
        var keys = KeysProviderOf(JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption));
        var handler = new ConfigurationHandler(
            options.Object,
            SingleIssuer.LicensedCatalog,
            Mock.Of<ILogoutNotifier>(),
            clientAuthenticator.Object,
            metadata.Object,
            Mock.Of<IScopesAndClaimsProvider>(),
            algorithms.Object,
            keys,
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
        // RFC 9449 section 5.1: dpop_signing_alg_values_supported signals "support for DPoP in general", which FAPI
        // 1.0 Advanced refuses (Part 2 section 8.2), so the document carries none
        Assert.Equal(narrowed ? null : signing, document.DpopSigningAlgValuesSupported);
        Assert.Equal(admitted, document.AuthorizationSigningAlgValuesSupported);
        Assert.Equal([SigningAlgorithms.None, ..admitted], document.UserInfoSigningAlgValuesSupported);
        Assert.Equal(encryption, document.RequestObjectEncryptionAlgValuesSupported);
        Assert.Equal(encryption, document.AuthorizationEncryptionAlgValuesSupported);
        Assert.Equal(encryption, document.IntrospectionEncryptionAlgValuesSupported);
    }

    /// <summary>
    /// Every response type the registered builders make up, implicit, hybrid and none included, in the order the
    /// authorization endpoint metadata lists them.
    /// </summary>
    private static readonly string[] EveryResponseType =
    [
        ResponseTypes.Code,
        ResponseTypes.Token,
        ResponseTypes.IdToken,
        ResponseTypes.None,
        $"{ResponseTypes.Code} {ResponseTypes.Token}",
        $"{ResponseTypes.Code} {ResponseTypes.IdToken}",
        $"{ResponseTypes.Token} {ResponseTypes.IdToken}",
        $"{ResponseTypes.Code} {ResponseTypes.Token} {ResponseTypes.IdToken}",
    ];

    /// <summary>
    /// FAPI 2.0 Security Profile section 5.3.2.2: "authorization servers shall require the value of response_type
    /// described in [RFC6749] to be code", and the tenant's profile binds every client it serves, so the document of a
    /// tenant held to any profile of the FAPI 2.0 family lists code alone (OpenID Connect Discovery 1.0 section 3, RFC
    /// 8414 section 2: the values "that this authorization server supports"). A tenant held to no profile lists every
    /// response type the server makes up.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2, true)]
    [InlineData(ClientSecurityProfile.Fapi2SignedAuthorizationRequests, true)]
    [InlineData(ClientSecurityProfile.Fapi2SignedAuthorizationResponses, true)]
    [InlineData(ClientSecurityProfile.Fapi2MessageSigning, true)]
    [InlineData(ClientSecurityProfile.None, false)]
    public async Task TheDocument_ListsTheResponseTypesTheTenantsProfileAdmits(
        ClientSecurityProfile profile,
        bool codeOnly)
    {
        var metadata = new Mock<IAuthorizationMetadataProvider>();
        metadata.Setup(m => m.ResponseTypesSupported).Returns(EveryResponseType);
        var handler = HandlerFor(Mock.Of<IAuthServiceKeysProvider>(MockBehavior.Strict), metadata.Object);

        var document = await handler.HandleAsync(new TestIssuer { DefaultSecurityProfile = profile }.ToTenant());

        Assert.Equal(codeOnly ? [ResponseTypes.Code] : EveryResponseType, document.ResponseTypesSupported);
    }

    /// <summary>
    /// FAPI 1.0 Part 2 section 5.2.2 has the server "require the response_type value code id_token, or the
    /// response_type value code in conjunction with the response_mode value jwt", so the document of a tenant held to
    /// FAPI 1.0 Advanced lists those two response types alone.
    /// </summary>
    [Fact]
    public async Task TheDocument_ListsTheSignedResponseTypes_WhereTheTenantsProfileRequiresASignedResponse()
    {
        var metadata = new Mock<IAuthorizationMetadataProvider>();
        metadata.Setup(m => m.ResponseTypesSupported).Returns(EveryResponseType);
        var handler = HandlerFor(Mock.Of<IAuthServiceKeysProvider>(MockBehavior.Strict), metadata.Object);

        var document = await handler.HandleAsync(
            new TestIssuer { DefaultSecurityProfile = ClientSecurityProfile.Fapi1Advanced }.ToTenant());

        Assert.Equal(
            [ResponseTypes.Code, $"{ResponseTypes.Code} {ResponseTypes.IdToken}"],
            document.ResponseTypesSupported);
    }

    /// <summary>
    /// The implicit grant type is what a client registers for a response type returning a token or an ID token from
    /// the authorization endpoint (RFC 7591 section 2.1), which FAPI 2.0 Security Profile section 5.3.2.2 refuses, so
    /// the document of a tenant held to any profile of the FAPI 2.0 family does not list it (OpenID Connect Discovery
    /// 1.0 section 3, RFC 8414 section 2: the grant types "that this authorization server supports"). FAPI 1.0 Advanced
    /// admits code id_token, a hybrid response type, and so keeps it, as does a tenant held to no profile.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.Fapi2, false)]
    [InlineData(ClientSecurityProfile.Fapi2SignedAuthorizationRequests, false)]
    [InlineData(ClientSecurityProfile.Fapi2SignedAuthorizationResponses, false)]
    [InlineData(ClientSecurityProfile.Fapi2MessageSigning, false)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced, true)]
    [InlineData(ClientSecurityProfile.None, true)]
    public async Task TheDocument_ListsTheImplicitGrantType_OnlyWhereTheTenantsProfileAdmitsAnImplicitResponse(
        ClientSecurityProfile profile,
        bool implicitListed)
    {
        string[] grantTypes =
        [
            GrantTypes.AuthorizationCode,
            GrantTypes.Implicit,
            GrantTypes.RefreshToken,
            GrantTypes.ClientCredentials,
        ];
        var scopesAndClaims = new Mock<IScopesAndClaimsProvider>();
        scopesAndClaims.Setup(p => p.GrantTypesSupported).Returns(grantTypes);
        var handler = HandlerFor(
            Mock.Of<IAuthServiceKeysProvider>(MockBehavior.Strict),
            Mock.Of<IAuthorizationMetadataProvider>(),
            scopesAndClaims.Object);

        var document = await handler.HandleAsync(new TestIssuer { DefaultSecurityProfile = profile }.ToTenant());

        Assert.Equal(
            implicitListed ? grantTypes : grantTypes.Where(grantType => grantType != GrantTypes.Implicit),
            document.GrantTypesSupported);
    }

    /// <summary>
    /// The response types the document lists are exactly those the authorization endpoint accepts from some client of
    /// the tenant: a value listed and refused tells a client the server supports a flow it will not run, and a value
    /// accepted and not listed hides one it does. The server makes up every response type, the none flow included, as
    /// a host enabling the implicit and none flows does; the client is registered for all of them and states no
    /// profile, so only the tenant's profile decides. A value counts as accepted where it passes with the response
    /// mode the request leaves to the server or with jwt, which a profile requiring a signed response asks for.
    /// </summary>
    [Theory]
    [InlineData(ClientSecurityProfile.None)]
    [InlineData(ClientSecurityProfile.Fapi2)]
    [InlineData(ClientSecurityProfile.Fapi2SignedAuthorizationRequests)]
    [InlineData(ClientSecurityProfile.Fapi2SignedAuthorizationResponses)]
    [InlineData(ClientSecurityProfile.Fapi2MessageSigning)]
    [InlineData(ClientSecurityProfile.Fapi1Advanced)]
    public async Task TheDocument_ListsExactlyTheResponseTypesTheAuthorizationEndpointAccepts(ClientSecurityProfile profile)
    {
        IAuthorizationResponseBuilder[] builders =
        [
            Mock.Of<IAuthorizationResponseBuilder>(b => b.ResponseType == ResponseTypes.Code),
            Mock.Of<IAuthorizationResponseBuilder>(b => b.ResponseType == ResponseTypes.Token),
            Mock.Of<IAuthorizationResponseBuilder>(b => b.ResponseType == ResponseTypes.IdToken),
            Mock.Of<IAuthorizationResponseBuilder>(b => b.ResponseType == ResponseTypes.None),
        ];
        var tenant = new TestIssuer { DefaultSecurityProfile = profile }.ToTenant();
        var validator = new FlowTypeValidator(Mock.Of<ILogger<FlowTypeValidator>>(), builders);
        var everyResponseType = EveryResponseType.Select(responseType => responseType.Split(' ')).ToArray();

        async Task<bool> AcceptedAsync(string[] responseType)
        {
            foreach (var responseMode in new[] { null, ResponseModes.Jwt })
            {
                var context = new AuthorizationValidationContext(new AuthorizationRequest
                {
                    ClientId = TestConstants.DefaultClientId,
                    ResponseType = responseType,
                    ResponseMode = responseMode,
                })
                {
                    ClientInfo = new ClientInfo(TestConstants.DefaultClientId) { AllowedResponseTypes = everyResponseType },
                };

                if (await validator.ValidateAsync(tenant, context) is null)
                    return true;
            }

            return false;
        }

        var accepted = new List<string>();
        foreach (var responseType in everyResponseType)
        {
            if (await AcceptedAsync(responseType))
                accepted.Add(string.Join(' ', responseType));
        }

        // The metadata the server builds accepts request objects, so the handler asks for the keys to encrypt one to
        var handler = HandlerFor(KeysProviderOf(), new AuthorizationMetadataProvider(builders));
        var document = await handler.HandleAsync(tenant);

        Assert.Equal(accepted, document.ResponseTypesSupported);
    }

    private const string RsaDeclaringOaep256 = nameof(RsaDeclaringOaep256);
    private const string RsaDeclaringNone = nameof(RsaDeclaringNone);
    private const string EllipticCurveDeclaringNone = nameof(EllipticCurveDeclaringNone);
    private const string SymmetricOnly = nameof(SymmetricOnly);
    private const string NoKey = nameof(NoKey);

    private static readonly Dictionary<string, Func<JsonWebKey[]>> KeySets = new()
    {
        [RsaDeclaringOaep256] = () =>
            [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption, EncryptionAlgorithms.KeyManagement.RsaOaep256)],
        [RsaDeclaringNone] = () => [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption)],
        [EllipticCurveDeclaringNone] = () =>
        [
            JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, EncryptionAlgorithms.KeyManagement.EcdhEs)
                with { Algorithm = null },
        ],
        [SymmetricOnly] = () =>
        [
            new OctetJsonWebKey { KeyId = "service-tokens", KeyValue = new byte[32], Usage = PublicKeyUsages.Encryption },
        ],
        [NoKey] = () => [],
    };

    /// <summary>
    /// The key management algorithms listed for request objects are those the tenant's own published encryption keys
    /// open: a key declaring its algorithm opens only that one (RFC 8725 section 3.1), a key declaring none what its
    /// material performs, and a symmetric key, which the JWK set may not carry (OpenID Connect Discovery 1.0 section 3,
    /// jwks_uri), none a client could use. With no such key both lists are omitted, as section 4.2 requires of a claim
    /// with zero elements.
    /// </summary>
    [Theory]
    [InlineData(RsaDeclaringOaep256, new[] { EncryptionAlgorithms.KeyManagement.RsaOaep256 })]
    [InlineData(
        RsaDeclaringNone,
        new[]
        {
            EncryptionAlgorithms.KeyManagement.Rsa1_5,
            EncryptionAlgorithms.KeyManagement.RsaOaep,
            EncryptionAlgorithms.KeyManagement.RsaOaep256,
        })]
    [InlineData(EllipticCurveDeclaringNone, new[] { EncryptionAlgorithms.KeyManagement.EcdhEs })]
    [InlineData(SymmetricOnly, null)]
    [InlineData(NoKey, null)]
    public async Task TheDocument_ListsTheRequestObjectAlgorithmsTheTenantsKeysOpen(string keys, string[]? expected)
    {
        var handler = HandlerFor(KeysProviderOf(KeySets[keys]()));

        var document = await handler.HandleAsync(SingleIssuer.Tenant);

        Assert.Equal(expected, document.RequestObjectEncryptionAlgValuesSupported);
        Assert.Equal(
            expected is null ? null : [EncryptionAlgorithms.ContentEncryption.Aes256Gcm],
            document.RequestObjectEncryptionEncValuesSupported);
    }

    /// <summary>
    /// A server that accepts no request object lists no algorithm to encrypt one with, and asks for no key.
    /// </summary>
    [Fact]
    public async Task TheDocument_ListsNoRequestObjectEncryption_WhenRequestObjectsAreNotAccepted()
    {
        var handler = HandlerFor(
            Mock.Of<IAuthServiceKeysProvider>(MockBehavior.Strict),
            requestParameterSupported: false);

        var document = await handler.HandleAsync(SingleIssuer.Tenant);

        Assert.Null(document.RequestObjectEncryptionAlgValuesSupported);
        Assert.Null(document.RequestObjectEncryptionEncValuesSupported);
    }

    /// <summary>
    /// A key provider answering <paramref name="keys"/> for the test's tenant alone, so a handler asking for another
    /// tenant's keys fails its test.
    /// </summary>
    private static IAuthServiceKeysProvider KeysProviderOf(params JsonWebKey[] keys)
    {
        var provider = new Mock<IAuthServiceKeysProvider>(MockBehavior.Strict);
        provider
            .Setup(p => p.GetEncryptionKeys(TestTenant.Matched, false))
            .Returns(() => keys.ToAsyncEnumerable());
        return provider.Object;
    }

    /// <summary>
    /// A handler over a server registering a fixed set of request object encryption algorithms.
    /// </summary>
    private static ConfigurationHandler HandlerFor(IAuthServiceKeysProvider keys, bool requestParameterSupported = true)
    {
        var metadata = new Mock<IAuthorizationMetadataProvider>();
        metadata.Setup(m => m.RequestParameterSupported).Returns(requestParameterSupported);
        return HandlerFor(keys, metadata.Object);
    }

    /// <summary>
    /// A handler over <paramref name="metadata"/> and a server registering a fixed set of request object encryption
    /// algorithms.
    /// </summary>
    private static ConfigurationHandler HandlerFor(
        IAuthServiceKeysProvider keys,
        IAuthorizationMetadataProvider metadata,
        IScopesAndClaimsProvider? scopesAndClaims = null)
    {
        var algorithms = new Mock<IJwtAlgorithmsProvider>();
        algorithms.Setup(a => a.RequestObjectEncryptionAlgValuesSupported).Returns(
        [
            EncryptionAlgorithms.KeyManagement.Rsa1_5,
            EncryptionAlgorithms.KeyManagement.RsaOaep,
            EncryptionAlgorithms.KeyManagement.RsaOaep256,
            EncryptionAlgorithms.KeyManagement.EcdhEs,
            EncryptionAlgorithms.KeyManagement.Aes256KW,
            EncryptionAlgorithms.KeyManagement.Dir,
        ]);
        algorithms.Setup(a => a.RequestObjectEncryptionEncValuesSupported)
            .Returns([EncryptionAlgorithms.ContentEncryption.Aes256Gcm]);
        var options = new Mock<IOptionsSnapshot<OidcOptions>>();
        options.Setup(o => o.Value).Returns(new OidcOptions());
        var clientAuthenticator = new Mock<IClientAuthenticator>();
        clientAuthenticator.Setup(a => a.ClientAuthenticationMethodsSupported).Returns([]);

        return new ConfigurationHandler(
            options.Object,
            SingleIssuer.LicensedCatalog,
            Mock.Of<ILogoutNotifier>(),
            clientAuthenticator.Object,
            metadata,
            scopesAndClaims ?? Mock.Of<IScopesAndClaimsProvider>(),
            algorithms.Object,
            keys,
            [],
            Mock.Of<IAcrMetadataProvider>(),
            Mock.Of<IAuthorizationDetailsMetadataProvider>());
    }
}
