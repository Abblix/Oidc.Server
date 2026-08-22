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
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Revocation;

/// <summary>
/// Every <see cref="JsonWebTokenStatus"/> is decided deliberately by the decorator rather than by falling off
/// the end of its switch.
/// </summary>
/// <remarks>
/// The switch there has no <c>default</c> arm on purpose: acceptance is the right answer for a token nothing
/// is recorded about, so a loud default would throw on every ordinary request. That leaves the usual trap -
/// a status added later inherits acceptance in silence, and a silently accepted revoked token is the failure
/// this whole component exists to prevent. This walks the enum, so the next addition fails here until
/// somebody decides what it means.
/// </remarks>
public class TokenStatusCoverageTests
{
    private static readonly HashSet<JsonWebTokenStatus> Decided =
    [
        JsonWebTokenStatus.Unknown,
        JsonWebTokenStatus.Used,
        JsonWebTokenStatus.Revoked,
    ];

    [Fact]
    public void EveryStatus_HasADecidedOutcome()
    {
        var undecided = Enum.GetValues<JsonWebTokenStatus>().Where(status => !Decided.Contains(status)).ToArray();

        Assert.True(
            undecided.Length == 0,
            $"TokenStatusValidatorDecorator does not decide {string.Join(", ", undecided)}. Add the case to its "
            + $"switch and to this list, saying whether such a token is accepted or refused.");
    }

    /// <summary>
    /// And the outcomes are what the list claims, driven through the decorator rather than asserted about it:
    /// a list agreeing with itself would pass over a switch that had stopped refusing anything.
    /// </summary>
    [Theory]
    [InlineData(JsonWebTokenStatus.Unknown, null)]
    [InlineData(JsonWebTokenStatus.Used, JwtError.TokenAlreadyUsed)]
    [InlineData(JsonWebTokenStatus.Revoked, JwtError.TokenRevoked)]
    public async Task AStatus_ProducesTheOutcomeItIsListedWith(JsonWebTokenStatus status, JwtError? expected)
    {
        const string jwtId = "jti_1";

        var registry = new Mock<ITokenRegistry>(MockBehavior.Strict);
        registry.Setup(r => r.GetStatusAsync(jwtId)).ReturnsAsync(status);

        var cutoffs = new Mock<IRevocationCutoffRegistry>(MockBehavior.Strict);
        cutoffs
            .Setup(c => c.GetCutoffAsync(
                It.IsAny<RevocationScope>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((DateTimeOffset?)null);

        var clients = new Mock<IClientInfoProvider>(MockBehavior.Strict);
        clients
            .Setup(p => p.TryFindClientAsync(It.IsAny<string>()))
            .ReturnsAsync(new ClientInfo("client_1") { SubjectType = SubjectTypes.Public });

        var inner = new Mock<IJsonWebTokenValidator>(MockBehavior.Strict);
        Result<JsonWebToken, JwtValidationError> success = new JsonWebToken
        {
            Payload =
            {
                JwtId = jwtId,
                Subject = "user_1",
                IssuedAt = new DateTimeOffset(2024, 1, 15, 11, 0, 0, TimeSpan.Zero),
                ExpiresAt = new DateTimeOffset(2024, 1, 15, 12, 0, 0, TimeSpan.Zero),
            }
        };
        inner
            .Setup(v => v.ValidateAsync(It.IsAny<string>(), It.IsAny<ValidationParameters>()))
            .ReturnsAsync(success);

        var decorator = new TokenStatusValidatorDecorator(
            registry.Object,
            cutoffs.Object,
            clients.Object,
            new SubjectTypeConverter(),
            inner.Object);

        var result = await decorator.ValidateAsync("opaque.jwt", new ValidationParameters());

        if (expected is null)
        {
            Assert.True(result.TryGetSuccess(out _));
        }
        else
        {
            Assert.True(result.TryGetFailure(out var error));
            Assert.Equal(expected, error.Error);
        }
    }
}
