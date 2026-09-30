// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.DynamicClientManagement;

/// <summary>
/// A registration (RFC 7591) answers with what the store now holds, so one the store did not keep - raced by another
/// under the same id, or under an id the settings came to configure - is refused as a taken id is, and answers
/// with no credentials.
/// </summary>
public class RegisterClientRequestProcessorTests
{
    private readonly Mock<IClientInfoManager> _clients = new(MockBehavior.Strict);
    private readonly Mock<IRegistrationAccessTokenService> _tokens = new(MockBehavior.Loose);
    private readonly CapturingLogger<RegisterClientRequestProcessor> _logger = new();

    private RegisterClientRequestProcessor Processor() => Processor(_clients.Object);

    private RegisterClientRequestProcessor Processor(IClientInfoManager clients)
    {
        var credentials = new Mock<IClientCredentialFactory>(MockBehavior.Strict);
        credentials
            .Setup(c => c.Create(It.IsAny<string>(), "client-1"))
            .Returns(new ClientCredentials("client-1", "secret", null, null));

        var tokenIds = new Mock<ITokenIdGenerator>(MockBehavior.Strict);
        tokenIds.Setup(g => g.GenerateTokenId()).Returns("jti-1");

        _tokens
            .Setup(s => s.IssueTokenAsync(
                It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), It.IsAny<string>()))
            .ReturnsAsync("registration-access-token");

        return new RegisterClientRequestProcessor(
            _logger,
            credentials.Object, clients, TimeProvider.System, tokenIds.Object, _tokens.Object);
    }

    private static ValidClientRegistrationRequest Request() => new(
        new ClientRegistrationRequest
        {
            ClientId = "client-1",
            RedirectUris = [new Uri("https://client.example.com/cb")],
        },
        SectorIdentifier: null);

    [Fact]
    public async Task ARegistrationTheStoreKeeps_IsAnsweredWithItsToken()
    {
        _clients
            .Setup(c => c.TryAddClientAsync(It.Is<RegisteredClient>(r =>
                r.ClientInfo.ClientId == "client-1" && r.RegistrationAccessTokenId == "jti-1")))
            .ReturnsAsync(true);

        var result = await Processor().ProcessAsync(Request());

        Assert.True(result.TryGetSuccess(out var response));
        Assert.Equal("client-1", response.ClientId);
        _tokens.Verify(
            s => s.IssueTokenAsync("client-1", It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), "jti-1"),
            Times.Once);
    }

    [Fact]
    public async Task ARegistrationTheStoreDoesNotKeep_IsRefused()
    {
        _clients.Setup(c => c.TryAddClientAsync(It.IsAny<RegisteredClient>())).ReturnsAsync(false);

        var result = await Processor().ProcessAsync(Request());

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        var entry = Assert.Single(_logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal(LogEvents.DynamicClientManagement.RegisterClientRequestProcessor.RegistrationNotKept, entry.EventId.Id);
    }

    /// <summary>
    /// A token that cannot be issued leaves nothing stored: the client id stays free for the registrant to retry.
    /// </summary>
    [Fact]
    public async Task ATokenThatCannotBeIssued_LeavesNoClientStored()
    {
        var processor = Processor();
        _tokens
            .Setup(s => s.IssueTokenAsync(
                It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<TimeSpan?>(), It.IsAny<string>()))
            .ThrowsAsync(new InvalidOperationException("no signing key"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => processor.ProcessAsync(Request()));

        _clients.VerifyNoOtherCalls();
    }

    /// <summary>
    /// Against a real store, the second of two registrations under one id is refused, and the first is what is kept.
    /// </summary>
    [Fact]
    public async Task TheSecondOfTwoRegistrationsUnderOneId_IsRefusedByTheStore()
    {
        var store = new ClientInfoStorage(
            SingleIssuer.Settings,
            new SingleIssuerLocal<Dictionary<string, ClientInfo>>(),
            new SingleIssuerLocal<ConcurrentDictionary<string, RegisteredClient>>());
        var processor = Processor(store);

        Assert.True((await processor.ProcessAsync(Request())).TryGetSuccess(out _));
        Assert.True((await processor.ProcessAsync(Request())).TryGetFailure(out var error));
        Assert.Equal(ErrorCodes.InvalidClientMetadata, error.Error);
        Assert.NotNull(await store.TryFindRegisteredClientAsync("client-1"));
    }

    /// <summary>
    /// Records the level and event of each entry.
    /// </summary>
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, EventId EventId)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, eventId));
    }
}
