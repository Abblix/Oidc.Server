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
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DeviceAuthorization;

/// <summary>
/// Verifies that <see cref="UserCodeVerificationService"/> canonicalizes the user-entered code
/// before lookup (RFC 8628 Section 6.1), so the readability variants a user may type — a different
/// case or copied-in dashes — resolve to the same stored device authorization request rather than
/// being rejected as invalid.
/// </summary>
public class UserCodeVerificationServiceTests
{
    private const string CanonicalUserCode = "WDJBMJHT";
    private const string DeviceCode = "device-code-123";
    private const string ClientId = "test-client";

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
            storage.Object,
            rateLimiter.Object,
            normalizer,
            Mock.Of<IHttpContextAccessor>());
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
}
