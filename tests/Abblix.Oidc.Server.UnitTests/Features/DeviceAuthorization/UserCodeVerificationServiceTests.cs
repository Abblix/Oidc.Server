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
        // ExpiresAt is set because it is DateTimeOffset.MinValue otherwise, which is in the past.
        // Measured: leave it unset and all four canonicalization rows go RED once the lifetime is
        // checked, because verification then answers InvalidUserCode. They are not vacuous - they
        // measure canonicalization exactly as named - so an expired fixture would break them for a
        // reason having nothing to do with what they are for.
        var request = new DeviceAuthorizationRequest(ClientId, ["openid"], null, CanonicalUserCode)
        {
            ExpiresAt = Now.AddMinutes(5),
        };

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
        // has nothing to enforce (RFC 9396 section 9).
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
    public async Task Approve_WithAnyTypeWhereTheRequestAskedForNone_RefusesAndLeavesTheRequestPending()
    {
        // A request carrying nothing is judged strictly rather than skipped, so every type in the grant
        // escapes. Pinned on its own because the strict reading is a decision and its opposite is one
        // early return away: skipping a null baseline would let a host attach any authority at all to a
        // device that asked for none, which is the wider version of the case above rather than a
        // different one.
        //
        // CIBA takes the opposite reading deliberately, for a reason that does not hold here: its stored
        // member arrived after the flow shipped, so a null there says the request predates the field. The
        // device record has carried this member since the flow's first release.
        var service = BuildService(requestedDetails: null, out var logs);

        var approved = await service.ApproveAsync(
            CanonicalUserCode,
            GrantWith(new JsonArray(new JsonObject { ["type"] = "admin_access" })));

        Assert.False(approved);
        var warning = Assert.Single(logs.Entries, entry => entry.Level == LogLevel.Warning);
        Assert.Contains("admin_access", warning.Message);
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

    /// <summary>
    /// The decision is applied to the record read from the DEVICE-CODE lookup, and that record is what
    /// is written back.
    /// </summary>
    /// <remarks>
    /// The whole of this change is which object the decision lands on, and nothing measured it: every
    /// other fixture answers both lookups with ONE instance, so deciding the stale record and deciding
    /// the fresh one are the same call. Two mutants live in that blind spot and both leave the suite
    /// green: deciding the stale record writes back one still reading Pending, so the device polls
    /// authorization_pending for ever; deciding the fresh one and WRITING the stale one loses the
    /// approval just as quietly. Only the identity assertion below sees the second.
    /// <para>
    /// So the two lookups return DISTINCT pending objects here, which is what production does anyway:
    /// the storage deserializes on every call.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ApproveAsync_AppliesTheDecision_ToTheRecordItReadForTheWrite()
    {
        var fromUserCode = new DeviceAuthorizationRequest(ClientId, ["openid"], null, CanonicalUserCode)
        {
            ExpiresAt = Now.AddMinutes(5),
        };

        var fromDeviceCode = new DeviceAuthorizationRequest(ClientId, ["openid"], null, CanonicalUserCode)
        {
            ExpiresAt = Now.AddMinutes(5),
        };

        var storage = new Mock<IDeviceAuthorizationStorage>(MockBehavior.Loose);
        storage
            .Setup(store => store.TryGetByUserCodeAsync(It.IsAny<string>()))
            .ReturnsAsync((string code) => code == CanonicalUserCode ? (DeviceCode, fromUserCode) : null);

        storage
            .Setup(store => store.TryGetByDeviceCodeAsync(It.IsAny<string>()))
            .ReturnsAsync((string code) => code == DeviceCode ? fromDeviceCode : null);

        DeviceAuthorizationRequest? written = null;
        storage
            .Setup(store => store.UpdateAsync(
                It.IsAny<string>(), It.IsAny<DeviceAuthorizationRequest>(), It.IsAny<TimeSpan>()))
            .Callback<string, DeviceAuthorizationRequest, TimeSpan>((_, r, _) => written = r)
            .Returns(Task.CompletedTask);

        var service = new UserCodeVerificationService(
            new CapturingLogger<UserCodeVerificationService>(),
            storage.Object,
            Mock.Of<IUserCodeRateLimiter>(),
            new UserCodeNormalizer(Options.Create(DeviceOptions())),
            Mock.Of<IRequestInfoProvider>(),
            new FakeTimeProvider(Now));

        Assert.True(await service.ApproveAsync(CanonicalUserCode, GrantWith(null)));

        // The object identity is the assertion. Both records carry the same fields, so comparing values
        // would pass on either one.
        Assert.Same(fromDeviceCode, written);
        Assert.Equal(DeviceAuthorizationStatus.Authorized, fromDeviceCode.Status);

        // And the stale one was left alone, which is what a caller reading it back would rely on.
        Assert.Equal(DeviceAuthorizationStatus.Pending, fromUserCode.Status);
    }

    /// <summary>
    /// A record past its lifetime is refused, and the refusal counts as a failed attempt.
    /// </summary>
    /// <remarks>
    /// Verification is the step the end user reaches FIRST, and it was the only one of the three
    /// deciding on <c>Status</c> alone. Its two siblings on the same record both refuse an expired one,
    /// so the user was shown a consent screen for a code that <c>ApproveAsync</c> would then refuse
    /// without a reason.
    /// <para>
    /// The rate-limit half is the one with teeth. Answering valid ran <c>RecordSuccessAsync</c>, which
    /// resets the per-code failure counter - so somebody holding one expired-but-pending code could
    /// clear that bucket at will and the brute-force budget for it never filled. An expired code is as
    /// dead as a used one and earns the same treatment.
    /// </para>
    /// <para>
    /// The answer is <see cref="InvalidUserCode"/> rather than a new result type because that type's own
    /// contract already says so: "was not found or has expired". The gap was the implementation, not the
    /// vocabulary.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Verify_OnAPendingRecordPastItsLifetime_RefusesAndCountsAFailure()
    {
        var expired = new DeviceAuthorizationRequest(ClientId, ["openid"], null, CanonicalUserCode)
        {
            ExpiresAt = Now.AddSeconds(-1),
        };

        var storage = new Mock<IDeviceAuthorizationStorage>(MockBehavior.Loose);
        storage
            .Setup(store => store.TryGetByUserCodeAsync(It.IsAny<string>()))
            .ReturnsAsync((string code) => code == CanonicalUserCode ? (DeviceCode, expired) : null);

        var rateLimiter = new Mock<IUserCodeRateLimiter>(MockBehavior.Loose);
        rateLimiter
            .Setup(limiter => limiter.CheckAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync((Result<bool, TimeSpan>)true);

        var service = new UserCodeVerificationService(
            new CapturingLogger<UserCodeVerificationService>(),
            storage.Object,
            rateLimiter.Object,
            new UserCodeNormalizer(Options.Create(DeviceOptions())),
            Mock.Of<IRequestInfoProvider>(),
            new FakeTimeProvider(Now));

        var result = await service.VerifyAsync(CanonicalUserCode);

        Assert.IsType<InvalidUserCode>(result);

        // Both halves, because a refusal that still reset the counter would satisfy the line above.
        rateLimiter.Verify(
            limiter => limiter.RecordFailureAsync(CanonicalUserCode, It.IsAny<string>()), Times.Once);
        rateLimiter.Verify(
            limiter => limiter.RecordSuccessAsync(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    /// <summary>
    /// The approval and the denial refuse a record past its lifetime, and each holds the predicate's
    /// boundary on its own.
    /// </summary>
    /// <remarks>
    /// Both guards existed before this change and nothing measured either: deleting them at the base
    /// left the suite green. Now that one predicate decides all three callers, a single edit moves three
    /// verdicts, so each caller gets a row rather than trusting the one on verification.
    /// <para>
    /// The instant chosen is the expiry itself, because that is the boundary a mutation moves: at
    /// exactly <c>ExpiresAt</c> the lifetime is over, and relaxing the comparison to <c>&gt;=</c> is
    /// what these rows exist to turn red.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ADecisionOnARecordAtItsExpiry_IsRefused(bool approving)
    {
        var expired = new DeviceAuthorizationRequest(ClientId, ["openid"], null, CanonicalUserCode)
        {
            ExpiresAt = Now,
        };

        var storage = new Mock<IDeviceAuthorizationStorage>(MockBehavior.Loose);
        storage
            .Setup(store => store.TryGetByUserCodeAsync(It.IsAny<string>()))
            .ReturnsAsync((string code) => code == CanonicalUserCode ? (DeviceCode, expired) : null);
        storage
            .Setup(store => store.TryGetByDeviceCodeAsync(It.IsAny<string>()))
            .ReturnsAsync((string code) => code == DeviceCode ? expired : null);

        var service = new UserCodeVerificationService(
            new CapturingLogger<UserCodeVerificationService>(),
            storage.Object,
            Mock.Of<IUserCodeRateLimiter>(),
            new UserCodeNormalizer(Options.Create(DeviceOptions())),
            Mock.Of<IRequestInfoProvider>(),
            new FakeTimeProvider(Now));

        var decided = approving
            ? await service.ApproveAsync(CanonicalUserCode, GrantWith(null))
            : await service.DenyAsync(CanonicalUserCode);

        Assert.False(decided);

        // The record is untouched, which is the half a bare false does not say: a decision written with
        // a non-positive cache TTL is what refusing here avoids.
        Assert.Equal(DeviceAuthorizationStatus.Pending, expired.Status);
        storage.Verify(
            store => store.UpdateAsync(
                It.IsAny<string>(), It.IsAny<DeviceAuthorizationRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);
    }

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

        // The decision is applied to the record as it stands at the write, so a fixture that answers the
        // user-code lookup and not this one is describing a record consumed in between - which is its own
        // row rather than the arrangement these tests want.
        storage
            .Setup(store => store.TryGetByDeviceCodeAsync(It.IsAny<string>()))
            .ReturnsAsync((string code) => code == DeviceCode ? request : null);

        logs = new CapturingLogger<UserCodeVerificationService>();
        return new UserCodeVerificationService(
            logs,
            storage.Object,
            Mock.Of<IUserCodeRateLimiter>(),
            new UserCodeNormalizer(Options.Create(DeviceOptions())),
            Mock.Of<IRequestInfoProvider>(),
            new FakeTimeProvider(Now));
    }

    /// <summary>
    /// A decision taken on a record that stopped being pending while the decision was being taken does
    /// not write that record back.
    /// </summary>
    /// <remarks>
    /// Approval reads the record, checks its status, and writes it back. Between those the record can
    /// move, in two ways, and the guard covers a record that is no longer pending rather than either of
    /// them by name.
    /// <para>
    /// A poll can redeem the device code and REMOVE it, and the write then restores an authorized record
    /// carrying its grant. A later poll finds it, and a second full token set is issued for one device
    /// code. The authorization-code path has a net for this, the reuse decorator inspecting IssuedTokens
    /// on the claimed grant; the device path has none, so nothing downstream catches it.
    /// </para>
    /// <para>
    /// Or another decision can land FIRST, leaving the record present and decided. Writing over it
    /// reverses somebody's answer: an approval overwriting a denial hands the device the tokens the end
    /// user refused. This half is the one with no removal in it, so a guard written for the first would
    /// pass every row of the first and none of this.
    /// </para>
    /// <para>
    /// What the re-read finds is arranged at the moment of the re-read rather than by racing two callers,
    /// so the rows measure the ordering the code guarantees rather than one a scheduler happened to
    /// produce. Where the record survives, the re-read returns a DISTINCT object, which is what makes
    /// "wrote the stale one" a different outcome from "wrote the fresh one" instead of the same.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(true, null)]
    [InlineData(false, null)]
    [InlineData(true, DeviceAuthorizationStatus.Denied)]
    [InlineData(true, DeviceAuthorizationStatus.Authorized)]
    [InlineData(false, DeviceAuthorizationStatus.Authorized)]
    [InlineData(false, DeviceAuthorizationStatus.Denied)]
    public async Task ADecisionOnARecordNoLongerPending_IsNotWrittenBack(
        bool approving, DeviceAuthorizationStatus? advancedTo)
    {
        var request = new DeviceAuthorizationRequest(ClientId, ["openid"], null, CanonicalUserCode)
        {
            ExpiresAt = Now.AddMinutes(5),
        };

        // What the re-read finds. Null is the record consumed and gone; a status is another decision
        // having landed first, on a record that is still there.
        var current = advancedTo is null
            ? null
            : new DeviceAuthorizationRequest(ClientId, ["openid"], null, CanonicalUserCode)
            {
                ExpiresAt = Now.AddMinutes(5),
                Status = advancedTo.Value,
            };

        var storage = new Mock<IDeviceAuthorizationStorage>(MockBehavior.Loose);
        storage
            .Setup(store => store.TryGetByUserCodeAsync(It.IsAny<string>()))
            .ReturnsAsync((string code) => code == CanonicalUserCode ? (DeviceCode, request) : null);

        storage
            .Setup(store => store.TryGetByDeviceCodeAsync(It.IsAny<string>()))
            .ReturnsAsync(current);

        var service = new UserCodeVerificationService(
            new CapturingLogger<UserCodeVerificationService>(),
            storage.Object,
            Mock.Of<IUserCodeRateLimiter>(),
            new UserCodeNormalizer(Options.Create(DeviceOptions())),
            Mock.Of<IRequestInfoProvider>(),
            new FakeTimeProvider(Now));

        var decided = approving
            ? await service.ApproveAsync(CanonicalUserCode, GrantWith(null))
            : await service.DenyAsync(CanonicalUserCode);

        Assert.False(decided);
        storage.Verify(
            store => store.UpdateAsync(It.IsAny<string>(), It.IsAny<DeviceAuthorizationRequest>(), It.IsAny<TimeSpan>()),
            Times.Never);
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
