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
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DeviceAuthorization;

/// <summary>
/// Verifies the per-IP rate-limiting invariant in <see cref="UserCodeRateLimiter"/> (RFC 8628
/// Section 5.2). The per-user-code counter and the per-IP counter protect against different
/// attacks: the per-user-code backoff slows guessing of a single code, while the per-IP counter
/// caps how many failures a single source may accumulate across many distinct codes. A successful
/// verification legitimately clears the per-user-code backoff, but it must NOT clear the per-IP
/// counter — otherwise an attacker who occasionally lands a valid code can reset the cross-code
/// brute-force budget at will.
/// </summary>
public class UserCodeRateLimiterTests
{
    private const string UserCode = "WDJB-MJHT";
    private const string ClientIdentifier = "203.0.113.7";
    private const string UserCodeKey = "rate-limit:user-code:WDJB-MJHT";
    private const string IpKey = "rate-limit:ip:203.0.113.7";

    private readonly Mock<IEntityStorage> _storage;
    private readonly UserCodeRateLimiter _rateLimiter;

    public UserCodeRateLimiterTests()
    {
        _storage = new Mock<IEntityStorage>(MockBehavior.Loose);

        var keyFactory = new Mock<IEntityStorageKeyFactory>(MockBehavior.Loose);
        keyFactory.Setup(f => f.UserCodeRateLimitKey(UserCode)).Returns(UserCodeKey);
        keyFactory.Setup(f => f.IpRateLimitKey(ClientIdentifier)).Returns(IpKey);

        _rateLimiter = new UserCodeRateLimiter(
            NullLogger<UserCodeRateLimiter>.Instance,
            _storage.Object,
            keyFactory.Object,
            TimeProvider.System,
            Options.Create(new OidcOptions { DeviceAuthorization = CreateDeviceAuthorizationOptions() }));
    }

    private static DeviceAuthorizationOptions CreateDeviceAuthorizationOptions() => new()
    {
        CodeLifetime = TimeSpan.FromMinutes(5),
        PollingInterval = TimeSpan.FromSeconds(5),
        DeviceCodeLength = 32,
        UserCodeLength = 8,
        VerificationUri = new Uri("https://auth.example.com/device"),
    };

    [Fact]
    public async Task RecordSuccess_ClearsPerUserCodeBackoff()
    {
        await _rateLimiter.RecordSuccessAsync(UserCode, ClientIdentifier);

        _storage.Verify(
            s => s.RemoveAsync(UserCodeKey, It.IsAny<CancellationToken?>()),
            Times.Once);
    }

    [Fact]
    public async Task RecordSuccess_DoesNotClearPerIpCounter()
    {
        // A successful verification must not wipe the cross-code per-IP brute-force budget.
        await _rateLimiter.RecordSuccessAsync(UserCode, ClientIdentifier);

        _storage.Verify(
            s => s.RemoveAsync(IpKey, It.IsAny<CancellationToken?>()),
            Times.Never);
    }
}
