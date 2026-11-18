// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Features.Hashing;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;
using Abblix.Utils;
using Abblix.Oidc.Server.Common;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// Unit tests for <see cref="CompositeClientAuthenticator"/> verifying the composite pattern
/// for aggregating multiple client authentication strategies.
/// Tests cover authentication delegation, short-circuit behavior, and method aggregation.
/// </summary>
public class CompositeClientAuthenticatorTests
{
    /// <summary>
    /// Verifies composite with no authenticators returns null.
    /// Edge case: empty authenticator list.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithNoAuthenticators_ShouldReturnNull()
    {
        // Arrange
        var composite = CreateCompositeAuthenticator();
        var request = new ClientRequest();

        // Act
        var result = await composite.TryAuthenticateClientAsync(SingleIssuer.Tenant, request);

        // Assert
        Assert.False(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Verifies single authenticator that succeeds returns ClientInfo.
    /// Basic success case with one authenticator.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithSingleSuccessfulAuthenticator_ShouldReturnClientInfo()
    {
        // Arrange
        var clientInfo = new ClientInfo("test-client");
        var authenticator = Presenting();
        authenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(clientInfo);

        var composite = CreateCompositeAuthenticator(authenticator.Object);
        var request = new ClientRequest();

        // Act
        var result = await composite.TryAuthenticateClientAsync(SingleIssuer.Tenant, request);

        // Assert
        Assert.True(result.TryGetSuccess(out _));
        Assert.Equal("test-client", result.GetSuccess().ClientId);
        authenticator.Verify(a => a.TryAuthenticateClientAsync(TestTenant.Matched, request), Times.Once);
    }

    /// <summary>
    /// Verifies single authenticator that fails returns null.
    /// Basic failure case with one authenticator.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithSingleFailingAuthenticator_ShouldReturnNull()
    {
        // Arrange
        var authenticator = Presenting();
        authenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(ClientAuthenticationFailures.InvalidCredential);

        var composite = CreateCompositeAuthenticator(authenticator.Object);
        var request = new ClientRequest();

        // Act
        var result = await composite.TryAuthenticateClientAsync(SingleIssuer.Tenant, request);

        // Assert
        Assert.False(result.TryGetSuccess(out _));
        authenticator.Verify(a => a.TryAuthenticateClientAsync(TestTenant.Matched, request), Times.Once);
    }

    /// <summary>
    /// Verifies first successful authenticator short-circuits the chain.
    /// Per composite pattern, should not call subsequent authenticators after success.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithFirstSucceeding_ShouldNotCallSecond()
    {
        // Arrange
        var clientInfo = new ClientInfo("test-client");

        var firstAuthenticator = Presenting();
        firstAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(clientInfo);

        var secondAuthenticator = Presenting();
        // Should NOT be called

        var composite = CreateCompositeAuthenticator(firstAuthenticator.Object, secondAuthenticator.Object);
        var request = new ClientRequest();

        // Act
        var result = await composite.TryAuthenticateClientAsync(SingleIssuer.Tenant, request);

        // Assert
        Assert.True(result.TryGetSuccess(out _));
        Assert.Equal("test-client", result.GetSuccess().ClientId);
        firstAuthenticator.Verify(a => a.TryAuthenticateClientAsync(TestTenant.Matched, request), Times.Once);
        secondAuthenticator.Verify(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()), Times.Never);
    }

    /// <summary>
    /// Verifies second authenticator is tried when first fails.
    /// Chain-of-responsibility pattern: try each in sequence until success.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithFirstFailingSecondSucceeding_ShouldReturnFromSecond()
    {
        // Arrange
        var clientInfo = new ClientInfo("test-client-2");

        var firstAuthenticator = Presenting();
        firstAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(ClientAuthenticationFailures.InvalidCredential);

        var secondAuthenticator = Presenting();
        secondAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(clientInfo);

        var composite = CreateCompositeAuthenticator(firstAuthenticator.Object, secondAuthenticator.Object);
        var request = new ClientRequest();

        // Act
        var result = await composite.TryAuthenticateClientAsync(SingleIssuer.Tenant, request);

        // Assert
        Assert.True(result.TryGetSuccess(out _));
        Assert.Equal("test-client-2", result.GetSuccess().ClientId);
        firstAuthenticator.Verify(a => a.TryAuthenticateClientAsync(TestTenant.Matched, request), Times.Once);
        secondAuthenticator.Verify(a => a.TryAuthenticateClientAsync(TestTenant.Matched, request), Times.Once);
    }

    /// <summary>
    /// Verifies all authenticators tried when all fail.
    /// Should exhaust all options before returning null.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithAllFailing_ShouldReturnNull()
    {
        // Arrange
        var firstAuthenticator = Presenting();
        firstAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(ClientAuthenticationFailures.InvalidCredential);

        var secondAuthenticator = Presenting();
        secondAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(ClientAuthenticationFailures.InvalidCredential);

        var thirdAuthenticator = Presenting();
        thirdAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(ClientAuthenticationFailures.InvalidCredential);

        var composite = CreateCompositeAuthenticator(
            firstAuthenticator.Object,
            secondAuthenticator.Object,
            thirdAuthenticator.Object);
        var request = new ClientRequest();

        // Act
        var result = await composite.TryAuthenticateClientAsync(SingleIssuer.Tenant, request);

        // Assert
        Assert.False(result.TryGetSuccess(out _));
        firstAuthenticator.Verify(a => a.TryAuthenticateClientAsync(TestTenant.Matched, request), Times.Once);
        secondAuthenticator.Verify(a => a.TryAuthenticateClientAsync(TestTenant.Matched, request), Times.Once);
        thirdAuthenticator.Verify(a => a.TryAuthenticateClientAsync(TestTenant.Matched, request), Times.Once);
    }

    /// <summary>
    /// Verifies ClientAuthenticationMethodsSupported aggregates all methods.
    /// Composite should expose all methods from all authenticators.
    /// </summary>
    [Fact]
    public void ClientAuthenticationMethodsSupported_ShouldAggregateAllMethods()
    {
        // Arrange
        var firstAuthenticator = new Mock<IClientAuthenticator>();
        firstAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.ClientSecretBasic, ClientAuthenticationMethods.ClientSecretPost]);

        var secondAuthenticator = new Mock<IClientAuthenticator>();
        secondAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.PrivateKeyJwt]);

        var composite = CreateCompositeAuthenticator(firstAuthenticator.Object, secondAuthenticator.Object);

        // Act
        var methods = composite.ClientAuthenticationMethodsSupported.ToArray();

        // Assert
        Assert.Equal(3, methods.Length);
        Assert.Contains(ClientAuthenticationMethods.ClientSecretBasic, methods);
        Assert.Contains(ClientAuthenticationMethods.ClientSecretPost, methods);
        Assert.Contains(ClientAuthenticationMethods.PrivateKeyJwt, methods);
    }

    /// <summary>
    /// Verifies ClientAuthenticationMethodsSupported with no authenticators returns empty.
    /// Edge case: empty authenticator list.
    /// </summary>
    [Fact]
    public void ClientAuthenticationMethodsSupported_WithNoAuthenticators_ShouldReturnEmpty()
    {
        // Arrange
        var composite = CreateCompositeAuthenticator();

        // Act
        var methods = composite.ClientAuthenticationMethodsSupported.ToArray();

        // Assert
        Assert.Empty(methods);
    }

    /// <summary>
    /// Verifies duplicate methods are included (not deduplicated).
    /// Composite doesn't filter duplicates - that's acceptable.
    /// </summary>
    [Fact]
    public void ClientAuthenticationMethodsSupported_WithDuplicateMethods_ShouldIncludeDuplicates()
    {
        // Arrange
        var firstAuthenticator = new Mock<IClientAuthenticator>();
        firstAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.ClientSecretBasic]);

        var secondAuthenticator = new Mock<IClientAuthenticator>();
        secondAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns([ClientAuthenticationMethods.ClientSecretBasic]);

        var composite = CreateCompositeAuthenticator(firstAuthenticator.Object, secondAuthenticator.Object);

        // Act
        var methods = composite.ClientAuthenticationMethodsSupported.ToArray();

        // Assert
        Assert.Equal(2, methods.Length);
        Assert.All(methods, m => Assert.Equal(ClientAuthenticationMethods.ClientSecretBasic, m));
    }

    /// <summary>
    /// Verifies authentication order matches constructor order.
    /// First authenticator in params should be tried first.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_ShouldRespectAuthenticatorOrder()
    {
        // Arrange
        var callOrder = new System.Collections.Generic.List<int>();

        var firstAuthenticator = Presenting();
        firstAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(ClientAuthenticationFailures.InvalidCredential)
            .Callback(() => callOrder.Add(1));

        var secondAuthenticator = Presenting();
        secondAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(ClientAuthenticationFailures.InvalidCredential)
            .Callback(() => callOrder.Add(2));

        var thirdAuthenticator = Presenting();
        thirdAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(ClientAuthenticationFailures.InvalidCredential)
            .Callback(() => callOrder.Add(3));

        var composite = CreateCompositeAuthenticator(
            firstAuthenticator.Object,
            secondAuthenticator.Object,
            thirdAuthenticator.Object);
        var request = new ClientRequest();

        // Act
        await composite.TryAuthenticateClientAsync(SingleIssuer.Tenant, request);

        // Assert
        Assert.Equal(new[] { 1, 2, 3 }, callOrder);
    }

    /// <summary>
    /// Verifies same ClientRequest instance passed to all authenticators.
    /// Each authenticator should receive the original request object.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_ShouldPassSameRequestToAllAuthenticators()
    {
        // Arrange
        var capturedRequests = new System.Collections.Generic.List<ClientRequest>();

        var firstAuthenticator = Presenting();
        firstAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync((TenantDefinition _, ClientRequest r) =>
            {
                capturedRequests.Add(r);
                return ClientAuthenticationFailures.NoCredential;
            });

        var secondAuthenticator = Presenting();
        secondAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync((TenantDefinition _, ClientRequest r) =>
            {
                capturedRequests.Add(r);
                return ClientAuthenticationFailures.NoCredential;
            });

        var composite = CreateCompositeAuthenticator(firstAuthenticator.Object, secondAuthenticator.Object);
        var request = new ClientRequest { ClientId = "test-client" };

        // Act
        await composite.TryAuthenticateClientAsync(SingleIssuer.Tenant, request);

        // Assert
        Assert.Equal(2, capturedRequests.Count);
        Assert.Same(request, capturedRequests[0]);
        Assert.Same(request, capturedRequests[1]);
    }

    /// <summary>
    /// Creates CompositeClientAuthenticator instance using reflection to access internal constructor.
    /// </summary>
    private static IClientAuthenticator CreateCompositeAuthenticator(params IClientAuthenticator[] authenticators)
    {
        var type = typeof(IClientAuthenticator).Assembly.GetTypes()
            .First(t => t.Name == "CompositeClientAuthenticator");

        return (IClientAuthenticator)Activator.CreateInstance(type, [authenticators])!;
    }

    private static IClientAuthenticator Answering(Abblix.Utils.Result<ClientInfo, OidcError> answer)
    {
        var authenticator = new Mock<IClientAuthenticator>();
        authenticator
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(answer);
        return authenticator.Object;
    }

    /// <summary>
    /// The composite presents no credential only where every authenticator says none was presented to it; one that
    /// refused a presented credential decides the refusal, and one that authenticates decides the answer.
    /// </summary>
    [Fact]
    public async Task TheThreeAnswers_Combine()
    {
        var client = new ClientInfo("test-client");
        var none = ClientAuthenticationFailures.NoCredential;
        var refused = ClientAuthenticationFailures.InvalidCredential;

        var allNone = await CreateCompositeAuthenticator(Answering(none), Answering(none))
            .TryAuthenticateClientAsync(SingleIssuer.Tenant, new ClientRequest());
        var oneRefused = await CreateCompositeAuthenticator(Answering(none), Answering(refused), Answering(none))
            .TryAuthenticateClientAsync(SingleIssuer.Tenant, new ClientRequest());
        var oneAuthenticates = await CreateCompositeAuthenticator(Answering(refused), Answering(client))
            .TryAuthenticateClientAsync(SingleIssuer.Tenant, new ClientRequest());

        Assert.Same(none, allNone.GetFailure());
        Assert.Same(refused, oneRefused.GetFailure());
        Assert.Same(client, oneAuthenticates.GetSuccess());
    }

    private static Mock<IClientAuthenticator> Presenting(params string[] places)
    {
        var authenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        authenticator
            .Setup(a => a.FindPresentedCredentialsAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(places);
        return authenticator;
    }

    /// <summary>
    /// RFC 6749 section 2.3: "The client MUST NOT use more than one authentication method in each request". Credentials
    /// in two places are refused as more than one method before any authenticator checks one: the strict mocks would
    /// throw if authentication were attempted.
    /// </summary>
    [Fact]
    public async Task CredentialsInTwoPlaces_AreRefusedBeforeAnyIsChecked()
    {
        var header = Presenting(nameof(ClientRequest.AuthorizationHeaderLines));
        var body = Presenting(nameof(ClientRequest.ClientSecret));
        var none = Presenting();

        var result = await CreateCompositeAuthenticator(none.Object, header.Object, body.Object)
            .TryAuthenticateClientAsync(SingleIssuer.Tenant, new ClientRequest());

        Assert.Same(ClientAuthenticationFailures.MoreThanOneMethod, result.GetFailure());
        Assert.Equal(ErrorCodes.InvalidRequest, result.GetFailure().Error);
    }

    /// <summary>
    /// One credential read by two authenticators, as a client assertion is by both JWT ones, is one method.
    /// </summary>
    [Fact]
    public async Task OnePlaceNamedByTwoAuthenticators_IsOneMethod()
    {
        var client = new ClientInfo("test-client");
        var first = Presenting(nameof(ClientRequest.ClientAssertion));
        first
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(ClientAuthenticationFailures.InvalidCredential);
        var second = Presenting(nameof(ClientRequest.ClientAssertion));
        second
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(client);

        var composite = CreateCompositeAuthenticator(first.Object, second.Object);
        var result = await composite.TryAuthenticateClientAsync(SingleIssuer.Tenant, new ClientRequest());

        Assert.Same(client, result.GetSuccess());
        Assert.Equal(
            [nameof(ClientRequest.ClientAssertion)],
            await composite.FindPresentedCredentialsAsync(SingleIssuer.Tenant, new ClientRequest()));
    }

    /// <summary>
    /// A client registered for tls_client_auth presenting its certificate and a body secret uses two methods (RFC 8705
    /// section 2 makes the certificate its credential).
    /// </summary>
    [Fact]
    public async Task CertificateOfAMutualTlsClientBesideABodySecret_IsMoreThanOneMethod()
    {
        var clients = new Mock<IClientInfoProvider>();
        clients
            .Setup(x => x.TryFindClientAsync(TestTenant.Matched, "tls-client"))
            .ReturnsAsync(new ClientInfo("tls-client") { TokenEndpointAuthMethod = ClientAuthenticationMethods.TlsClientAuth });
        using var key = System.Security.Cryptography.RSA.Create(2048);
        using var certificate = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=tls-client",
                key,
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(TimeProvider.System.GetUtcNow().AddDays(-1), TimeProvider.System.GetUtcNow().AddDays(1));

        var composite = CreateCompositeAuthenticator(
            new ClientSecretPostAuthenticator(
                NullLogger<ClientSecretPostAuthenticator>.Instance,
                clients.Object,
                TimeProvider.System,
                new Mock<IHashService>().Object),
            new TlsMetadataClientAuthenticator(NullLogger<TlsMetadataClientAuthenticator>.Instance, clients.Object));

        var result = await composite.TryAuthenticateClientAsync(
            SingleIssuer.Tenant,
            new ClientRequest { ClientId = "tls-client", ClientSecret = "secret", ClientCertificate = certificate });

        Assert.Same(ClientAuthenticationFailures.MoreThanOneMethod, result.GetFailure());
    }

    /// <summary>
    /// The client a public client's request names, with its secret authenticators and the none one composed in the
    /// order the server registers them.
    /// </summary>
    private static IClientAuthenticator PublicClientComposite(out ClientInfo publicClient)
    {
        var client = new ClientInfo("public-client") { TokenEndpointAuthMethod = ClientAuthenticationMethods.None };
        publicClient = client;
        var clients = new Mock<IClientInfoProvider>();
        clients
            .Setup(x => x.TryFindClientAsync(TestTenant.Matched, client.ClientId))
            .ReturnsAsync(client);

        return CreateCompositeAuthenticator(
            new NoneClientAuthenticator(NullLogger<NoneClientAuthenticator>.Instance, clients.Object),
            new ClientSecretPostAuthenticator(
                NullLogger<ClientSecretPostAuthenticator>.Instance,
                clients.Object,
                TimeProvider.System,
                new Mock<IHashService>().Object),
            new ClientSecretBasicAuthenticator(
                NullLogger<ClientSecretBasicAuthenticator>.Instance,
                clients.Object,
                TimeProvider.System,
                new Mock<IHashService>().Object),
            new TlsMetadataClientAuthenticator(NullLogger<TlsMetadataClientAuthenticator>.Instance, clients.Object));
    }

    /// <summary>
    /// OpenID Connect Core 1.0 section 9 defines none as "a Public Client with no Client Secret or other authentication
    /// mechanism", so a request naming a public client and presenting a credential uses a method the client is not
    /// registered for, which RFC 6749 section 5.2 answers invalid_client ("unsupported authentication method"): the
    /// refusal of the authenticator reading the credential stands, and the client_id alone does not authenticate.
    /// </summary>
    [Fact]
    public async Task PublicClientPresentingABodySecret_IsRefused()
    {
        var composite = PublicClientComposite(out var publicClient);

        var result = await composite.TryAuthenticateClientAsync(
            SingleIssuer.Tenant,
            new ClientRequest { ClientId = publicClient.ClientId, ClientSecret = "wrong-secret" });

        Assert.Same(ClientAuthenticationFailures.InvalidCredential, result.GetFailure());
    }

    /// <summary>
    /// The same through the Authorization header, the client_id in the body naming the public client.
    /// </summary>
    [Fact]
    public async Task PublicClientPresentingABasicHeader_IsRefused()
    {
        var composite = PublicClientComposite(out var publicClient);
        var credentials = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes($"{publicClient.ClientId}:wrong-secret"));

        var result = await composite.TryAuthenticateClientAsync(
            SingleIssuer.Tenant,
            new ClientRequest
            {
                ClientId = publicClient.ClientId,
                AuthorizationHeaderLines = [$"{TokenTypes.Basic} {credentials}"],
            });

        Assert.Same(ClientAuthenticationFailures.InvalidCredential, result.GetFailure());
    }

    /// <summary>
    /// The same for a credential of a host's own form: an authenticator naming no place where the request presents a
    /// credential is not asked, whichever authenticator reads that credential.
    /// </summary>
    [Fact]
    public async Task AuthenticatorShownNoPresentedCredential_DoesNotDecide()
    {
        var reader = Presenting(nameof(ClientRequest.ClientAssertion));
        reader
            .Setup(a => a.TryAuthenticateClientAsync(TestTenant.Matched, It.IsAny<ClientRequest>()))
            .ReturnsAsync(ClientAuthenticationFailures.InvalidCredential);

        // Strict and set up for no authentication: it would throw if asked
        var bystander = Presenting();

        var result = await CreateCompositeAuthenticator(bystander.Object, reader.Object)
            .TryAuthenticateClientAsync(SingleIssuer.Tenant, new ClientRequest());

        Assert.Same(ClientAuthenticationFailures.InvalidCredential, result.GetFailure());
    }

    /// <summary>
    /// The control of the rows above: with no credential presented, the public client is served on its client_id, and a
    /// TLS certificate on the connection is not a credential of a client registered for none (RFC 8705 section 4 has
    /// certificate-bound tokens used without mutual-TLS client authentication), so it is served beside one too.
    /// </summary>
    [Fact]
    public async Task PublicClientPresentingNoCredential_IsServed()
    {
        var composite = PublicClientComposite(out var publicClient);
        using var key = System.Security.Cryptography.RSA.Create(2048);
        using var certificate = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=public-client",
                key,
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(TimeProvider.System.GetUtcNow().AddDays(-1), TimeProvider.System.GetUtcNow().AddDays(1));

        var alone = await composite.TryAuthenticateClientAsync(
            SingleIssuer.Tenant, new ClientRequest { ClientId = publicClient.ClientId });
        var besideACertificate = await composite.TryAuthenticateClientAsync(
            SingleIssuer.Tenant,
            new ClientRequest { ClientId = publicClient.ClientId, ClientCertificate = certificate });

        Assert.Same(publicClient, alone.GetSuccess());
        Assert.Same(publicClient, besideACertificate.GetSuccess());
    }
}
