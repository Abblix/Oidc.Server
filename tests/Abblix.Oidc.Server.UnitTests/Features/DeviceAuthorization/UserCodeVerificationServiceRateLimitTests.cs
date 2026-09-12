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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DeviceAuthorization;

/// <summary>
/// What the limits do when the thing that verifies a user code and the thing that counts attempts are the
/// real ones, working against a real store.
/// </summary>
/// <remarks>
/// Every other suite touching these two replaces one of them: the verification suite hands the service a
/// stand-in limiter that always answers "go ahead", and the limiter suite calls the limiter directly. So
/// the decision that matters - WHICH attempts are charged to a code - was made in the seam between them,
/// where nothing looked.
/// <para>
/// The question these rows settle is whose attempts they are. A guess at a string nobody was issued is not
/// an attempt against any code: there is no code. Charging it to the string would count the one thing an
/// attacker never repeats, and would let somebody spend the allowance of a code that has not been issued
/// yet. What bounds guessing at nothing is the per-address count.
/// </para>
/// </remarks>
public class UserCodeVerificationServiceRateLimitTests
{
    // Digits, because the alphabet a deployment gets by default is digits and normalization drops every
    // character outside it - a letter code would arrive here as an empty string.
    private const string TheCode = "12345678";
    private const string Address = "203.0.113.7";

    private readonly DateTimeOffset _now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
    private readonly IEntityStorage _rateLimitStore = new DistributedCacheStorage(
        new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
        new JsonBinarySerializer());

    private static DeviceAuthorizationOptions DeviceOptions() => new()
    {
        CodeLifetime = TimeSpan.FromMinutes(5),
        PollingInterval = TimeSpan.FromSeconds(5),
        DeviceCodeLength = 32,
        UserCodeLength = 8,
        VerificationUri = new Uri("https://auth.example.com/device"),
        MaxUserCodeAttempts = 5,
        // Above the per-code allowance, so the growing pause cannot answer before the allowance does and
        // these rows measure the allowance they are named for.
        MaxFailuresBeforeBackoff = 6,
        MaxIpFailuresPerMinute = 100,
        RateLimitWindow = TimeSpan.FromMinutes(1),
        MaxBackoffDuration = TimeSpan.FromHours(1),
        IpRateLimitStateExpiration = TimeSpan.FromMinutes(2),
    };

    /// <summary>
    /// Builds the real pair over a store that holds the named code, or holds nothing.
    /// </summary>
    private UserCodeVerificationService ServiceOver(
        DeviceAuthorizationRequest? request, string address = Address)
    {
        var deviceStorage = new Mock<IDeviceAuthorizationStorage>(MockBehavior.Loose);
        deviceStorage
            .Setup(s => s.TryGetByUserCodeAsync(TheCode))
            .ReturnsAsync(request == null ? null : ("device-code", request));

        // Approval re-reads by DEVICE code before it writes, so without this the approval path refuses for
        // a reason having nothing to do with the limits - and a row about the limits could not tell the two
        // apart. Measured: with this absent, removing the limiter from approval changed no test at all.
        deviceStorage
            .Setup(s => s.TryGetByDeviceCodeAsync("device-code"))
            .ReturnsAsync(request);

        var requestInfo = new Mock<IRequestInfoProvider>(MockBehavior.Loose);
        requestInfo.Setup(p => p.RemoteIpAddress).Returns(IPAddress.Parse(address));

        var options = Options.Create(new OidcOptions { DeviceAuthorization = DeviceOptions() });

        return new UserCodeVerificationService(
            NullLogger<UserCodeVerificationService>.Instance,
            deviceStorage.Object,
            new UserCodeRateLimiter(
                NullLogger<UserCodeRateLimiter>.Instance,
                _rateLimitStore,
                new EntityStorageKeyFactory(),
                new FakeTimeProvider(_now),
                options),
            new UserCodeNormalizer(options),
            requestInfo.Object,
            new FakeTimeProvider(_now));
    }

    private DeviceAuthorizationRequest PendingCode() =>
        new("a-client", ["openid"], null, TheCode) { ExpiresAt = _now.AddMinutes(5) };

    /// <summary>
    /// Guesses at a code that does not exist do not spend the allowance of a code issued afterwards.
    /// </summary>
    /// <remarks>
    /// The attempts are made while nothing holds that value, and then it becomes a real, pending,
    /// unexpired code - which is what happens when a guesser works through the space while codes are
    /// being issued. The person reading this code off their screen must be able to use it.
    /// </remarks>
    [Fact]
    public async Task GuessesAtACodeThatDoesNotExist_DoNotSpendTheAllowanceOfACodeIssuedLater()
    {
        var guessing = ServiceOver(null);
        for (var i = 0; i < 10; i++)
            Assert.IsType<InvalidUserCode>(await guessing.VerifyAsync(TheCode));

        var issued = ServiceOver(PendingCode());

        Assert.IsType<ValidUserCode>(await issued.VerifyAsync(TheCode));
    }

    /// <summary>
    /// A guessing search that rotates addresses runs into the server's own budget for the window.
    /// </summary>
    /// <remarks>
    /// This is the limit the other two cannot replace. The per-code count never sees such a search,
    /// because it never submits one value twice; the per-address count never sees it either, because each
    /// guess comes from somewhere new. The budget counts the attempts themselves, whoever made them and
    /// whatever they named, which is why it is what stops the search - and why it also refuses a person
    /// who mistypes while it holds.
    /// </remarks>
    [Fact]
    public async Task AGuessingSearchThatRotatesAddresses_RunsIntoTheServersBudget()
    {
        // A hundred guesses, each from its own address, each at a value nobody was issued.
        for (var i = 0; i < 100; i++)
        {
            var guessing = ServiceOver(null, address: "203.0.113." + (i % 250 + 1));
            Assert.IsType<InvalidUserCode>(await guessing.VerifyAsync("9999" + i.ToString("0000")));
        }

        // A real, pending code from an address that has spent nothing of its own is refused too: the
        // budget is the server's, not the source's.
        var issued = ServiceOver(PendingCode(), address: "198.51.100.23");

        Assert.IsType<InvalidUserCode>(await issued.VerifyAsync(TheCode));
    }

    /// <summary>
    /// Approving and denying a code ask the same limits verification asks.
    /// </summary>
    /// <remarks>
    /// Both take a user code as a string and answer whether it names a live authorization, which is the
    /// question a guesser is asking - and approval is also the call that grants. Unasked, they are the same
    /// oracle with no counting behind it.
    /// <para>
    /// Driven against a LIVE, pending code with the server's budget spent, because that is the only state
    /// where the limits are the reason for the refusal: a code in any other state is refused by its state,
    /// which a row cannot tell apart from a limit doing its job.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ApprovingAndDenying_AreCountedLikeVerifying()
    {
        for (var i = 0; i < 100; i++)
        {
            var guessing = ServiceOver(null, address: "203.0.113." + (i % 250 + 1));
            await guessing.VerifyAsync("9999" + i.ToString("0000"));
        }

        var service = ServiceOver(PendingCode());

        var grant = new AuthorizedGrant(
            new AuthSession("a-user", "a-session", _now, "device"),
            new AuthorizationContext("a-client", ["openid"], null));

        Assert.False(await service.ApproveAsync(TheCode, grant));
        Assert.False(await service.DenyAsync(TheCode));
    }

    /// <summary>
    /// Attempts against a code that exists belong to that code, and spend its allowance.
    /// </summary>
    /// <remarks>
    /// A code that is no longer pending is the case: the value names a real authorization, the attempt is
    /// against it, and repeating it is what the per-code allowance is for.
    /// </remarks>
    [Fact]
    public async Task AttemptsAgainstACodeThatExists_SpendItsAllowance()
    {
        var used = PendingCode();
        used.Status = DeviceAuthorizationStatus.Authorized;
        var service = ServiceOver(used);

        for (var i = 0; i < 5; i++)
            Assert.IsType<UserCodeAlreadyUsed>(await service.VerifyAsync(TheCode));

        // The sixth attempt meets the allowance rather than the status, so the answer changes: the
        // service does not look the code up at all once its attempts are spent.
        Assert.IsType<InvalidUserCode>(await service.VerifyAsync(TheCode));
    }
}
