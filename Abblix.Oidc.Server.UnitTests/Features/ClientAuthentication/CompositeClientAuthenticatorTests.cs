// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Moq;
using Xunit;

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
        var result = await composite.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
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
        var authenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        authenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync(clientInfo);

        var composite = CreateCompositeAuthenticator(authenticator.Object);
        var request = new ClientRequest();

        // Act
        var result = await composite.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("test-client", result.ClientId);
        authenticator.Verify(a => a.TryAuthenticateClientAsync(request), Times.Once);
    }

    /// <summary>
    /// Verifies single authenticator that fails returns null.
    /// Basic failure case with one authenticator.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithSingleFailingAuthenticator_ShouldReturnNull()
    {
        // Arrange
        var authenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        authenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientInfo?)null);

        var composite = CreateCompositeAuthenticator(authenticator.Object);
        var request = new ClientRequest();

        // Act
        var result = await composite.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
        authenticator.Verify(a => a.TryAuthenticateClientAsync(request), Times.Once);
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

        var firstAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        firstAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync(clientInfo);

        var secondAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        // Should NOT be called

        var composite = CreateCompositeAuthenticator(firstAuthenticator.Object, secondAuthenticator.Object);
        var request = new ClientRequest();

        // Act
        var result = await composite.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("test-client", result.ClientId);
        firstAuthenticator.Verify(a => a.TryAuthenticateClientAsync(request), Times.Once);
        secondAuthenticator.Verify(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()), Times.Never);
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

        var firstAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        firstAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientInfo?)null);

        var secondAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        secondAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync(clientInfo);

        var composite = CreateCompositeAuthenticator(firstAuthenticator.Object, secondAuthenticator.Object);
        var request = new ClientRequest();

        // Act
        var result = await composite.TryAuthenticateClientAsync(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("test-client-2", result.ClientId);
        firstAuthenticator.Verify(a => a.TryAuthenticateClientAsync(request), Times.Once);
        secondAuthenticator.Verify(a => a.TryAuthenticateClientAsync(request), Times.Once);
    }

    /// <summary>
    /// Verifies all authenticators tried when all fail.
    /// Should exhaust all options before returning null.
    /// </summary>
    [Fact]
    public async Task TryAuthenticateClientAsync_WithAllFailing_ShouldReturnNull()
    {
        // Arrange
        var firstAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        firstAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientInfo?)null);

        var secondAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        secondAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientInfo?)null);

        var thirdAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        thirdAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientInfo?)null);

        var composite = CreateCompositeAuthenticator(
            firstAuthenticator.Object,
            secondAuthenticator.Object,
            thirdAuthenticator.Object);
        var request = new ClientRequest();

        // Act
        var result = await composite.TryAuthenticateClientAsync(request);

        // Assert
        Assert.Null(result);
        firstAuthenticator.Verify(a => a.TryAuthenticateClientAsync(request), Times.Once);
        secondAuthenticator.Verify(a => a.TryAuthenticateClientAsync(request), Times.Once);
        thirdAuthenticator.Verify(a => a.TryAuthenticateClientAsync(request), Times.Once);
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
            .Returns(new[] { ClientAuthenticationMethods.ClientSecretBasic, ClientAuthenticationMethods.ClientSecretPost });

        var secondAuthenticator = new Mock<IClientAuthenticator>();
        secondAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns(new[] { ClientAuthenticationMethods.PrivateKeyJwt });

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
            .Returns(new[] { ClientAuthenticationMethods.ClientSecretBasic });

        var secondAuthenticator = new Mock<IClientAuthenticator>();
        secondAuthenticator
            .Setup(a => a.ClientAuthenticationMethodsSupported)
            .Returns(new[] { ClientAuthenticationMethods.ClientSecretBasic });

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

        var firstAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        firstAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientInfo?)null)
            .Callback(() => callOrder.Add(1));

        var secondAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        secondAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientInfo?)null)
            .Callback(() => callOrder.Add(2));

        var thirdAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        thirdAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientInfo?)null)
            .Callback(() => callOrder.Add(3));

        var composite = CreateCompositeAuthenticator(
            firstAuthenticator.Object,
            secondAuthenticator.Object,
            thirdAuthenticator.Object);
        var request = new ClientRequest();

        // Act
        await composite.TryAuthenticateClientAsync(request);

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

        var firstAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        firstAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientRequest r) =>
            {
                capturedRequests.Add(r);
                return null;
            });

        var secondAuthenticator = new Mock<IClientAuthenticator>(MockBehavior.Strict);
        secondAuthenticator
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .ReturnsAsync((ClientRequest r) =>
            {
                capturedRequests.Add(r);
                return null;
            });

        var composite = CreateCompositeAuthenticator(firstAuthenticator.Object, secondAuthenticator.Object);
        var request = new ClientRequest { ClientId = "test-client" };

        // Act
        await composite.TryAuthenticateClientAsync(request);

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

        return (IClientAuthenticator)Activator.CreateInstance(type, new object[] { authenticators })!;
    }
}
