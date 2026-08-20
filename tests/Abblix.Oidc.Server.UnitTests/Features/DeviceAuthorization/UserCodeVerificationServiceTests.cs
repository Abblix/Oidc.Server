// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Utils;
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
}
