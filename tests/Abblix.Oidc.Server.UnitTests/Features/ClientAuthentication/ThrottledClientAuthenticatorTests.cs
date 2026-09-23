// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Net;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// What a sender that never authenticates successfully costs. Verifying a credential is not free - a client
/// assertion is a signature this server checks before it can say the credential is wrong - and no budget
/// charged to a client can reach such a sender, because it never proves to be one.
/// </summary>
public class ThrottledClientAuthenticatorTests
{
    /// <summary>
    /// Long enough that nothing replenishes a budget mid-test: what is being checked is the refusal, not the
    /// clock.
    /// </summary>
    private static readonly TimeSpan OneMinute = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Enough attempts that a budget of one would have refused long ago, so a run that answers every one of
    /// them says nothing was counted rather than that the sender stayed inside its allowance.
    /// </summary>
    private const int RequestsWellPastTheBudget = 10;

    private static readonly IPAddress Source = IPAddress.Parse("203.0.113.7");

    /// <summary>
    /// A second address, so a budget that stopped separating senders can be told from one that separates
    /// them.
    /// </summary>
    private static readonly IPAddress AnotherSource = IPAddress.Parse("203.0.113.8");

    private readonly Mock<IClientAuthenticator> _inner = new(MockBehavior.Strict);
    private readonly Mock<IRequestInfoProvider> _requestInfoProvider = new();

    public ThrottledClientAuthenticatorTests()
    {
        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns(Source);
    }

    private ThrottledClientAuthenticator CreateAuthenticator(int? permitLimit)
        => new(
            NullLogger<ThrottledClientAuthenticator>.Instance,
            _inner.Object,
            new AuthenticationFailureBudget(
                CallerRateLimiters.Create(
                    new AuthenticationFailureLimitOptions { PermitLimit = permitLimit, Window = OneMinute }),
                _requestInfoProvider.Object));

    private static ClientRequest CreateRequest() => new() { ClientId = TestConstants.DefaultClientId };

    [Fact]
    public async Task ASourcePastItsBudget_HasNoFurtherCredentialLookedAt()
    {
        // Arrange
        var authenticator = CreateAuthenticator(permitLimit: 1);
        _inner
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(null));

        // Act
        Assert.Null(await authenticator.TryAuthenticateClientAsync(CreateRequest()));
        var refusal = await Assert.ThrowsAsync<TooManyAuthenticationFailuresException>(
            () => authenticator.TryAuthenticateClientAsync(CreateRequest()));

        // Assert
        Assert.NotNull(refusal.RetryAfter);

        // The credential in the second request never reached the authenticator, which is the whole point.
        _inner.Verify(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()), Times.Once);
    }

    /// <summary>
    /// And two senders have two budgets. The address is what separates them, so a name that stopped
    /// separating them would turn a budget meant to price one sender's guessing into one bucket for
    /// everybody: a single sender could then close client authentication to every client of the server.
    /// </summary>
    [Fact]
    public async Task ASourceThatSpentItsBudget_LeavesAnotherSourceItsOwn()
    {
        // Arrange
        var authenticator = CreateAuthenticator(permitLimit: 1);
        _inner
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(null));

        // Act
        Assert.Null(await authenticator.TryAuthenticateClientAsync(CreateRequest()));
        await Assert.ThrowsAsync<TooManyAuthenticationFailuresException>(
            () => authenticator.TryAuthenticateClientAsync(CreateRequest()));

        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns(AnotherSource);

        // Assert
        Assert.Null(await authenticator.TryAuthenticateClientAsync(CreateRequest()));
    }

    /// <summary>
    /// One sender has one budget however its address is spelled. A dual-stack server reports the same peer as
    /// an IPv4 address over one socket and as the IPv4-mapped IPv6 form over the other, so a budget that took
    /// the spelling would give a sender guessing secrets one allowance per stack.
    /// </summary>
    [Fact]
    public async Task ASourceArrivingUnderBothAddressForms_SpendsOneBudget()
    {
        // Arrange
        var authenticator = CreateAuthenticator(permitLimit: 1);
        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns(IPAddress.Parse($"::ffff:{Source}"));
        _inner
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(null));

        // Act
        Assert.Null(await authenticator.TryAuthenticateClientAsync(CreateRequest()));

        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns(Source);

        // Assert
        await Assert.ThrowsAsync<TooManyAuthenticationFailuresException>(
            () => authenticator.TryAuthenticateClientAsync(CreateRequest()));
    }

    /// <summary>
    /// And the identifier of an interface does not buy that sender a second budget, because on a mapped
    /// address it names the mapping rather than the address inside it: the same peer arrives carrying one
    /// and then without, and the second request finds the first one's failure already counted.
    /// </summary>
    [Fact]
    public async Task ASourceArrivingUnderAMappedFormWithAnInterface_SpendsOneBudget()
    {
        // Arrange
        var authenticator = CreateAuthenticator(permitLimit: 1);
        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns(IPAddress.Parse($"::ffff:{Source}%5"));
        _inner
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(null));

        // Act
        Assert.Null(await authenticator.TryAuthenticateClientAsync(CreateRequest()));

        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns(Source);

        // Assert
        await Assert.ThrowsAsync<TooManyAuthenticationFailuresException>(
            () => authenticator.TryAuthenticateClientAsync(CreateRequest()));
    }

    /// <summary>
    /// Nothing successful is counted, so a busy client whose credentials verify never approaches a budget meant
    /// for senders whose credentials do not.
    /// </summary>
    [Fact]
    public async Task ASourceThatAuthenticates_IsNeverCounted()
    {
        // Arrange
        var authenticator = CreateAuthenticator(permitLimit: 1);
        var clientInfo = new ClientInfo(TestConstants.DefaultClientId);
        _inner
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(clientInfo));

        // Act, Assert
        for (var attempt = 0; attempt < RequestsWellPastTheBudget; attempt++)
            Assert.Same(clientInfo, await authenticator.TryAuthenticateClientAsync(CreateRequest()));
    }

    /// <summary>
    /// A request whose source cannot be named is not counted: nothing shared stands behind this budget for
    /// such a sender to spend, so one bucket for all of them would buy no protection and would let a single
    /// sender close every endpoint to everybody else arriving the same way.
    /// </summary>
    [Fact]
    public async Task ASourceThatCannotBeNamed_IsNeverCounted()
    {
        // Arrange
        _requestInfoProvider.Setup(p => p.RemoteIpAddress).Returns((IPAddress?)null);
        var authenticator = CreateAuthenticator(permitLimit: 1);
        _inner
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(null));

        // Act, Assert
        for (var attempt = 0; attempt < RequestsWellPastTheBudget; attempt++)
            Assert.Null(await authenticator.TryAuthenticateClientAsync(CreateRequest()));
    }

    /// <summary>
    /// Off is the default, and off means every credential is looked at however many have failed. A deployment
    /// turns this on when it knows that an address means one sender to it.
    /// </summary>
    [Fact]
    public async Task WithNoLimitConfigured_EveryCredentialIsStillLookedAt()
    {
        // Arrange
        Assert.Null(new AuthenticationFailureLimitOptions().PermitLimit);
        var authenticator = CreateAuthenticator(new AuthenticationFailureLimitOptions().PermitLimit);
        _inner
            .Setup(a => a.TryAuthenticateClientAsync(It.IsAny<ClientRequest>()))
            .Returns(Task.FromResult<ClientInfo?>(null));

        // Act, Assert
        for (var attempt = 0; attempt < RequestsWellPastTheBudget; attempt++)
            Assert.Null(await authenticator.TryAuthenticateClientAsync(CreateRequest()));
    }

    /// <summary>
    /// The decorator answers for the authenticator it wraps about which methods it supports, so a host reading
    /// the discovery document sees what the credentials can actually be.
    /// </summary>
    [Fact]
    public void TheSupportedMethods_AreTheOnesItWraps()
    {
        var methods = new[] { "client_secret_basic", "private_key_jwt" };
        _inner.Setup(a => a.ClientAuthenticationMethodsSupported).Returns(methods);

        Assert.Equal(methods, CreateAuthenticator(permitLimit: 1).ClientAuthenticationMethodsSupported);
    }
}
