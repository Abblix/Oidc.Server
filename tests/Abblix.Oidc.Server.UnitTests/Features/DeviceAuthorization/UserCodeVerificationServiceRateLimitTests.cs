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

    private readonly DateTimeOffset _now = new(2026, 1, 1, 12, 0, 20, TimeSpan.Zero);
    // Where a deployment sends these records: its serializer tries this one first, and this one writes a number
    // of zero as nothing and reads nothing back as an absent record, where the readable one keeps the two apart.
    private readonly IEntityStorage _rateLimitStore = new DistributedCacheStorage(
        new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
        new ProtobufSerializer());

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
        MaxAddressFailuresPerWindow = 100,
        RateLimitWindow = TimeSpan.FromMinutes(1),
        MaxBackoffDuration = TimeSpan.FromHours(1),
        RateLimitRetention = TimeSpan.FromMinutes(2),
    };

    /// <summary>
    /// Builds the real pair over a store that holds the named code, or holds nothing.
    /// </summary>
    private UserCodeVerificationService ServiceOver(
        DeviceAuthorizationRequest? request,
        string? address = Address,
        Action<DeviceAuthorizationOptions>? configure = null)
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
        requestInfo.Setup(p => p.RemoteIpAddress).Returns(address is null ? null : IPAddress.Parse(address));

        var deviceOptions = DeviceOptions();
        configure?.Invoke(deviceOptions);
        var options = Options.Create(new OidcOptions { DeviceAuthorization = deviceOptions });

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
    /// A refusal the typed value had nothing to do with says how long to wait.
    /// </summary>
    /// <remarks>
    /// The limiter computes that duration either way; until now the only caller dropped it and answered
    /// "invalid code", so a person refused because somebody else was guessing saw exactly what a typo
    /// shows. The server's budget and the per-address cap say nothing about the value that was typed, so
    /// naming them discloses nothing.
    /// </remarks>
    [Fact]
    public async Task ARefusalThatIsNotAboutTheCode_SaysHowLongToWait()
    {
        for (var i = 0; i < 100; i++)
        {
            var guessing = ServiceOver(null, address: "203.0.113." + (i % 250 + 1));
            await guessing.VerifyAsync("9999" + i.ToString("0000"));
        }

        var result = await ServiceOver(PendingCode(), address: "198.51.100.23").VerifyAsync(TheCode);

        var limited = Assert.IsType<TooManyUserCodeAttempts>(result);
        Assert.Equal(TimeSpan.FromSeconds(40), limited.RetryAfter);
    }

    /// <summary>
    /// A refusal by the growing pause is about the code, so it looks like an unknown code too.
    /// </summary>
    /// <remarks>
    /// Two refusals are about the typed value - the one that says its allowance is spent, and the pause it
    /// earns on the way there - and each decides separately whether it may be named. Naming this one would
    /// tell a guesser that the value it just typed is a code this server issued, which is the whole thing
    /// the plain refusal hides.
    /// <para>
    /// The pause is out of reach under the numbers the other rows use, where it is set above the allowance
    /// on purpose so those rows measure the allowance. Here it is set below, which is the ordinary
    /// arrangement and the one a deployment ships with.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ARefusalByTheGrowingPause_LooksLikeAnUnknownCode()
    {
        var used = PendingCode();
        used.Status = DeviceAuthorizationStatus.Authorized;
        var service = ServiceOver(used, configure: options => options.MaxFailuresBeforeBackoff = 2);

        await service.VerifyAsync(TheCode);
        await service.VerifyAsync(TheCode);

        Assert.IsType<InvalidUserCode>(await service.VerifyAsync(TheCode));
    }

    /// <summary>
    /// A refusal by the per-address cap says how long to wait.
    /// </summary>
    /// <remarks>
    /// Both refusals that count attempts rather than codes must say so - the cap on one address and the
    /// server's budget - and each carries that decision separately. This is the one an honest person meets
    /// while somebody else guesses from the same address or the same office, and answering it with
    /// "invalid code" tells them their correct code is wrong.
    /// </remarks>
    [Fact]
    public async Task ARefusalByTheAddressCap_SaysHowLongToWait()
    {
        void SmallCap(DeviceAuthorizationOptions options) => options.MaxAddressFailuresPerWindow = 3;

        for (var i = 0; i < 3; i++)
            await ServiceOver(null, configure: SmallCap).VerifyAsync("9999000" + i);

        var result = await ServiceOver(PendingCode(), configure: SmallCap).VerifyAsync(TheCode);

        var limited = Assert.IsType<TooManyUserCodeAttempts>(result);
        Assert.Equal(TimeSpan.FromSeconds(40), limited.RetryAfter);
    }

    /// <summary>
    /// And two addresses have two allowances, which is what makes the cap about a source rather than about
    /// everybody: a cap that stopped separating them would let one guesser close this page to every person
    /// waiting to type a code.
    /// </summary>
    [Fact]
    public async Task AnAddressThatSpentItsAllowance_LeavesAnotherAddressItsOwn()
    {
        void OneAttempt(DeviceAuthorizationOptions options) => options.MaxAddressFailuresPerWindow = 1;

        await ServiceOver(null, address: Address, configure: OneAttempt).VerifyAsync("99990000");

        var elsewhere = await ServiceOver(PendingCode(), address: "198.51.100.23", configure: OneAttempt)
            .VerifyAsync(TheCode);

        Assert.IsType<ValidUserCode>(elsewhere);
    }

    /// <summary>
    /// Attempts whose source the server cannot see share one allowance, because nothing tells them apart.
    /// </summary>
    [Fact]
    public async Task TwoAttemptsTheServerCannotSee_ShareOneAllowance()
    {
        void OneAttempt(DeviceAuthorizationOptions options) => options.MaxAddressFailuresPerWindow = 1;

        await ServiceOver(null, address: null, configure: OneAttempt).VerifyAsync("99990000");

        var next = await ServiceOver(PendingCode(), address: null, configure: OneAttempt)
            .VerifyAsync(TheCode);

        Assert.IsType<TooManyUserCodeAttempts>(next);
    }

    /// <summary>
    /// And what they spend is the server's own budget too, because an attempt nobody can attribute is
    /// still an attempt this server answered: the two counts are one rule, not one rule per source.
    /// </summary>
    [Fact]
    public async Task AnAttemptTheServerCannotSee_SpendsTheServersBudget()
    {
        void OneOfTheBudget(DeviceAuthorizationOptions options) => options.MaxFailedAttemptsPerWindow = 1;

        await ServiceOver(null, address: null, configure: OneOfTheBudget).VerifyAsync("99990000");

        var visible = await ServiceOver(PendingCode(), address: Address, configure: OneOfTheBudget)
            .VerifyAsync(TheCode);

        Assert.IsType<TooManyUserCodeAttempts>(visible);
    }

    /// <summary>
    /// And sharing one allowance is what keeps them off everybody else. Left uncounted, the only thing
    /// they spend is the budget the whole server shares, and that budget refuses every verification -
    /// including the callers whose address is in plain sight, who are the reason the page exists.
    /// </summary>
    [Fact]
    public async Task AFloodTheServerCannotSee_LeavesACallerItCanSeeAnswered()
    {
        void SmallBudget(DeviceAuthorizationOptions options)
        {
            options.MaxAddressFailuresPerWindow = 1;
            options.MaxFailedAttemptsPerWindow = 2;
        }

        for (var i = 0; i < 4; i++)
            await ServiceOver(null, address: null, configure: SmallBudget).VerifyAsync("9999000" + i);

        var visible = await ServiceOver(PendingCode(), address: Address, configure: SmallBudget)
            .VerifyAsync(TheCode);

        Assert.IsType<ValidUserCode>(visible);
    }

    /// <summary>
    /// One sender has one allowance however its address is spelled. A dual-stack server reports the same
    /// peer as an IPv4 address over one socket and as the IPv4-mapped IPv6 form over the other, so a cap
    /// that counted the spelling would give somebody guessing user codes one allowance per stack.
    /// </summary>
    [Fact]
    public async Task AnAddressArrivingUnderBothForms_SpendsOneAllowance()
    {
        void OneAttempt(DeviceAuthorizationOptions options) => options.MaxAddressFailuresPerWindow = 1;

        await ServiceOver(null, address: $"::ffff:{Address}", configure: OneAttempt).VerifyAsync("99990000");

        var result = await ServiceOver(PendingCode(), address: Address, configure: OneAttempt)
            .VerifyAsync(TheCode);

        Assert.IsType<TooManyUserCodeAttempts>(result);
    }

    /// <summary>
    /// A refusal that IS about the code is still indistinguishable from an unknown code.
    /// </summary>
    /// <remarks>
    /// Only a value the server issued can have attempts recorded against it, so an answer that admitted
    /// "this one is rate limited" would be an answer that the value is a real code. That is the disclosure
    /// the plain refusal exists to prevent, and it outweighs telling an honest caller how long to wait -
    /// for a code that is spent, waiting does not help anyway.
    /// </remarks>
    [Fact]
    public async Task ARefusalAboutTheCode_LooksLikeAnUnknownCode()
    {
        var used = PendingCode();
        used.Status = DeviceAuthorizationStatus.Authorized;
        var service = ServiceOver(used);

        for (var i = 0; i < 5; i++)
            await service.VerifyAsync(TheCode);

        Assert.IsType<InvalidUserCode>(await service.VerifyAsync(TheCode));
    }

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
    /// Guesses made through approval or denial at a value nobody holds do not spend the allowance of a code
    /// issued with that value later.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task GuessesThroughApprovalOrDenial_DoNotSpendTheAllowanceOfACodeIssuedLater(bool approve)
    {
        var guessing = ServiceOver(null);
        var grant = new AuthorizedGrant(
            new AuthSession("a-user", "a-session", _now, "device"),
            new AuthorizationContext("a-client", ["openid"], null));

        for (var i = 0; i < 10; i++)
        {
            if (approve)
                Assert.False(await guessing.ApproveAsync(TheCode, grant));
            else
                Assert.False(await guessing.DenyAsync(TheCode));
        }

        Assert.IsType<ValidUserCode>(await ServiceOver(PendingCode()).VerifyAsync(TheCode));
    }

    /// <summary>
    /// A code typed with a separator meets the same allowance as the code typed without one.
    /// </summary>
    [Fact]
    public async Task ACodeTypedWithASeparator_MeetsTheSameAllowance()
    {
        var limiter = new UserCodeRateLimiter(
            NullLogger<UserCodeRateLimiter>.Instance,
            _rateLimitStore,
            new EntityStorageKeyFactory(),
            new FakeTimeProvider(_now),
            Options.Create(new OidcOptions { DeviceAuthorization = DeviceOptions() }));

        for (var i = 0; i < 5; i++)
            await limiter.RecordFailureAsync(TheCode, Address);

        Assert.IsType<InvalidUserCode>(await ServiceOver(PendingCode()).VerifyAsync("1234-5678"));
    }

    /// <summary>
    /// Approval and denial accept a code typed with a separator, as verification does.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ApprovalAndDenial_AcceptACodeTypedWithASeparator(bool approve)
    {
        var service = ServiceOver(PendingCode());
        var grant = new AuthorizedGrant(
            new AuthSession("a-user", "a-session", _now, "device"),
            new AuthorizationContext("a-client", ["openid"], null));

        Assert.True(approve
            ? await service.ApproveAsync("1234-5678", grant)
            : await service.DenyAsync("1234-5678"));
    }

    /// <summary>
    /// Approving or denying a code that was already decided answers that nothing was decided.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DecidingACodeThatWasAlreadyDecided_AnswersFalse(bool approve)
    {
        var decided = PendingCode();
        decided.Status = DeviceAuthorizationStatus.Authorized;
        var service = ServiceOver(decided);
        var grant = new AuthorizedGrant(
            new AuthSession("a-user", "a-session", _now, "device"),
            new AuthorizationContext("a-client", ["openid"], null));

        Assert.False(approve
            ? await service.ApproveAsync(TheCode, grant)
            : await service.DenyAsync(TheCode));
    }

    /// <summary>
    /// Failures recorded against a value before it is successfully verified stop counting afterwards.
    /// </summary>
    [Fact]
    public async Task AVerifiedValue_DoesNotCarryTheFailuresOfItsEarlierLife()
    {
        void PauseAtThree(DeviceAuthorizationOptions options) => options.MaxFailuresBeforeBackoff = 3;

        var deviceOptions = DeviceOptions();
        PauseAtThree(deviceOptions);
        var limiter = new UserCodeRateLimiter(
            NullLogger<UserCodeRateLimiter>.Instance,
            _rateLimitStore,
            new EntityStorageKeyFactory(),
            new FakeTimeProvider(_now),
            Options.Create(new OidcOptions { DeviceAuthorization = deviceOptions }));

        await limiter.RecordFailureAsync(TheCode, Address);
        await limiter.RecordFailureAsync(TheCode, Address);

        Assert.IsType<ValidUserCode>(
            await ServiceOver(PendingCode(), configure: PauseAtThree).VerifyAsync(TheCode));

        await limiter.RecordFailureAsync(TheCode, Address);

        Assert.True((await limiter.CheckAsync(TheCode, Address)).TryGetSuccess(out _));
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
        // budget is the server's, not the source's. And the refusal names itself, because it is not about
        // the value that was typed.
        var issued = ServiceOver(PendingCode(), address: "198.51.100.23");

        Assert.IsType<TooManyUserCodeAttempts>(await issued.VerifyAsync(TheCode));
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
    /// A guess made at the approval or denial step is counted, not only refused.
    /// </summary>
    /// <remarks>
    /// Asking the limits and feeding them are two different things, and a row that only watches the asking
    /// leaves the feeding unheld - measured: removing the recording from both steps changed no test. An
    /// unrecorded guess is a free one, and these two steps take the same value from the same page.
    /// </remarks>
    [Fact]
    public async Task AGuessAtTheApprovalOrDenialStep_IsCounted()
    {
        var grant = new AuthorizedGrant(
            new AuthSession("a-user", "a-session", _now, "device"),
            new AuthorizationContext("a-client", ["openid"], null));

        // Ninety-nine wrong values through approval and denial, which is one short of the budget.
        for (var i = 0; i < 99; i++)
        {
            var guessing = ServiceOver(null, address: "203.0.113." + (i % 250 + 1));
            if (i % 2 == 0)
                await guessing.ApproveAsync("9999" + i.ToString("0000"), grant);
            else
                await guessing.DenyAsync("9999" + i.ToString("0000"));
        }

        // One more through verification spends it, which can only happen if the ninety-nine were counted.
        var last = ServiceOver(null, address: "198.51.100.1");
        await last.VerifyAsync("88888888");

        var issued = ServiceOver(PendingCode(), address: "198.51.100.23");

        Assert.IsType<TooManyUserCodeAttempts>(await issued.VerifyAsync(TheCode));
    }

    /// <summary>
    /// Approving or denying a code that can no longer be decided spends that code's own allowance.
    /// </summary>
    [Theory]
    [InlineData("already used", true)]
    [InlineData("expired", true)]
    [InlineData("already used", false)]
    [InlineData("expired", false)]
    public async Task DecidingACodeThatCannotBeDecided_SpendsThatCodesAllowance(string state, bool approve)
    {
        var request = PendingCode();
        switch (state)
        {
            case "already used":
                request.Status = DeviceAuthorizationStatus.Authorized;
                break;
            case "expired":
                request.ExpiresAt = _now.AddMinutes(-1);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(state), state, null);
        }

        var service = ServiceOver(request);
        var grant = new AuthorizedGrant(
            new AuthSession("a-user", "a-session", _now, "device"),
            new AuthorizationContext("a-client", ["openid"], null));

        for (var i = 0; i < 5; i++)
        {
            if (approve)
                await service.ApproveAsync(TheCode, grant);
            else
                await service.DenyAsync(TheCode);
        }

        var limiter = new UserCodeRateLimiter(
            NullLogger<UserCodeRateLimiter>.Instance,
            _rateLimitStore,
            new EntityStorageKeyFactory(),
            new FakeTimeProvider(_now),
            Options.Create(new OidcOptions { DeviceAuthorization = DeviceOptions() }));

        Assert.True((await limiter.CheckAsync(TheCode, Address)).TryGetFailure(out var refusal));
        Assert.True(refusal.AboutThisCode);
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
