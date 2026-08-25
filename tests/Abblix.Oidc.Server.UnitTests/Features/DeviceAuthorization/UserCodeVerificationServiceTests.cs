// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DeviceAuthorization;

/// <summary>
/// Verifies that <see cref="UserCodeVerificationService"/> canonicalizes the user-entered code
/// before lookup (RFC 8628 Section 6.1), so the readability variants a user may type - a different
/// case or copied-in dashes - resolve to the same stored device authorization request rather than
/// being rejected as invalid.
/// </summary>
public class UserCodeVerificationServiceTests
{
    private const string CanonicalUserCode = "WDJBMJHT";
    private const string DeviceCode = "device-code-123";
    private const string ClientId = "test-client";

    private static readonly DateTimeOffset Now = new(2024, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private readonly CapturingLogger<UserCodeVerificationService> _logs = new();
    private readonly UserCodeVerificationService _service;

    public UserCodeVerificationServiceTests()
    {
        var request = new DeviceAuthorizationRequest(ClientId, ["openid"], null, CanonicalUserCode);

        var storage = new Mock<IDeviceAuthorizationStorage>(MockBehavior.Loose);
        storage
            .Setup(s => s.TryGetByUserCodeAsync(It.IsAny<string>()))
            .ReturnsAsync((string code) =>
                code == CanonicalUserCode ? (DeviceCode, request) : null);

        var rateLimiter = new Mock<IUserCodeRateLimiter>(MockBehavior.Loose);
        rateLimiter
            .Setup(r => r.CheckAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync((Result<bool, TimeSpan>)true);

        var normalizer = new UserCodeNormalizer(Options.Create(new OidcOptions
        {
            DeviceAuthorization = new DeviceAuthorizationOptions
            {
                CodeLifetime = TimeSpan.FromMinutes(5),
                PollingInterval = TimeSpan.FromSeconds(5),
                DeviceCodeLength = 32,
                UserCodeLength = 8,
                VerificationUri = new Uri("https://auth.example.com/device"),
                UserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ",
            },
        }));

        _service = new UserCodeVerificationService(
            _logs,
            storage.Object,
            rateLimiter.Object,
            normalizer,
            Mock.Of<IRequestInfoProvider>(),
            new FakeTimeProvider(new DateTimeOffset(2024, 1, 1, 12, 0, 0, TimeSpan.Zero)));
    }

    [Theory]
    [InlineData("WDJBMJHT")]
    [InlineData("wdjbmjht")]
    [InlineData("WDJB-MJHT")]
    [InlineData(" wdjb-mjht ")]
    public async Task Verify_AcceptsReadabilityVariantsOfStoredCode(string entered)
    {
        var result = await _service.VerifyAsync(entered);

        var valid = Assert.IsType<ValidUserCode>(result);
        Assert.Equal(ClientId, valid.ClientId);
    }

    [Fact]
    public async Task Approve_WithoutTheRequestedAuthorizationDetails_SaysSo()
    {
        // Whether the entries reach the grant is the host's call, because only its verification page
        // knows what it displayed. What must not happen is that the omission passes unremarked: the
        // token that follows carries no authorization_details, and a resource server enforcing them
        // has nothing to enforce (RFC 9396 section 7).
        var requestedDetails = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var service = BuildService(requestedDetails, out var logs);

        var approved = await service.ApproveAsync(CanonicalUserCode, GrantWith(null));

        Assert.True(approved);
        var warning = Assert.Single(logs.Entries, entry => entry.Level == LogLevel.Warning);
        Assert.Contains(ClientId, warning.Message);

        // The count is part of the payload, and it is what tells the reader how much was lost.
        Assert.Contains("1", warning.Message);
        Assert.Equal(
            LogEvents.Device.UserCodeVerificationService.GrantedAuthorizationDetailsNotCarried,
            warning.EventId);
    }

    [Fact]
    public async Task Approve_WhenTheRequestCarriedNoDetails_SaysNothing()
    {
        // The silent case is the common one, so a detector that fired here would be waved away on every
        // approval and take the real finding with it.
        var service = BuildService(requestedDetails: null, out var logs);

        var approved = await service.ApproveAsync(CanonicalUserCode, GrantWith(null));

        Assert.True(approved);
        Assert.DoesNotContain(logs.Entries, entry => entry.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task Approve_WithATypeTheRequestNeverAskedFor_RefusesAndLeavesTheRequestPending()
    {
        // Narrowing is the host's to decide; widening is not. An approval carrying a type nobody
        // requested would give the device authority the client never asked for, so it is refused rather
        // than noted - and the request stays pending, so the user can still be asked again.
        var service = BuildService(
            requestedDetails: new JsonArray(new JsonObject { ["type"] = "account_information" }),
            out var logs);

        var approved = await service.ApproveAsync(
            CanonicalUserCode,
            GrantWith(new JsonArray(
                new JsonObject { ["type"] = "account_information" },
                new JsonObject { ["type"] = "payment_initiation" })));

        Assert.False(approved);
        var warning = Assert.Single(logs.Entries, entry => entry.Level == LogLevel.Warning);
        Assert.Contains("payment_initiation", warning.Message);
    }

    [Fact]
    public async Task Approve_CarryingTheAuthorizationDetails_SaysNothing()
    {
        var requestedDetails = new JsonArray(new JsonObject { ["type"] = "payment_initiation" });
        var service = BuildService(requestedDetails, out var logs);

        var approved = await service.ApproveAsync(
            CanonicalUserCode,
            GrantWith((JsonArray)requestedDetails.DeepClone()));

        Assert.True(approved);
        Assert.DoesNotContain(logs.Entries, entry => entry.Level == LogLevel.Warning);
    }

    private static AuthorizedGrant GrantWith(JsonArray? authorizationDetails)
        => new(
            new AuthSession("subject", "session", Now, "pwd"),
            new AuthorizationContext(ClientId, ["openid"], null)
            {
                AuthorizationDetails = authorizationDetails,
            });

    private static UserCodeVerificationService BuildService(
        JsonArray? requestedDetails,
        out CapturingLogger<UserCodeVerificationService> logs)
    {
        var request = new DeviceAuthorizationRequest(ClientId, ["openid"], null, CanonicalUserCode)
        {
            AuthorizationDetails = requestedDetails,
            ExpiresAt = Now.AddMinutes(5),
        };

        var storage = new Mock<IDeviceAuthorizationStorage>(MockBehavior.Loose);
        storage
            .Setup(store => store.TryGetByUserCodeAsync(It.IsAny<string>()))
            .ReturnsAsync((string code) => code == CanonicalUserCode ? (DeviceCode, request) : null);

        logs = new CapturingLogger<UserCodeVerificationService>();
        return new UserCodeVerificationService(
            logs,
            storage.Object,
            Mock.Of<IUserCodeRateLimiter>(),
            new UserCodeNormalizer(Options.Create(DeviceOptions())),
            Mock.Of<IRequestInfoProvider>(),
            new FakeTimeProvider(Now));
    }

    private static OidcOptions DeviceOptions() => new()
    {
        DeviceAuthorization = new DeviceAuthorizationOptions
        {
            CodeLifetime = TimeSpan.FromMinutes(5),
            PollingInterval = TimeSpan.FromSeconds(5),
            DeviceCodeLength = 32,
            UserCodeLength = 8,
            VerificationUri = new Uri("https://auth.example.com/device"),
            UserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ",
        },
    };

    /// <summary>Keeps what the service wrote, so a test can assert the absence as well as the presence.</summary>
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        private readonly List<(LogLevel Level, int EventId, string Message)> _entries = [];

        // The event id is kept because runbooks key off the number, so a test that ignored it would let
        // the number change without noticing.
        public IReadOnlyList<(LogLevel Level, int EventId, string Message)> Entries => _entries;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => _entries.Add((logLevel, eventId.Id, formatter(state, exception)));
    }
}
