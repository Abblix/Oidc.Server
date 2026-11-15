// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.MinimalApi.UnitTests;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;

/// <summary>
/// Reads the two challenges a response advertising both DPoP and Bearer carries (RFC 9449 section 7.2), each by the
/// challenge grammar, so a test compares a parameter rather than looking for it as text.
/// </summary>
public static class DualChallengeReader
{
    /// <summary>
    /// The DPoP and the Bearer challenge of the response, each exactly once and no other.
    /// </summary>
    /// <param name="response">The response to read.</param>
    internal static (ChallengeReader.Challenge DPoP, ChallengeReader.Challenge Bearer) Challenges(
        HttpResponseMessage response)
    {
        var challenges = response.Headers.WwwAuthenticate
            .Select(header => ChallengeReader.Parse(header.ToString()))
            .ToArray();

        Assert.Equal(2, challenges.Length);
        return (
            Assert.Single(challenges, challenge => challenge.Scheme == TokenTypes.DPoP),
            Assert.Single(challenges, challenge => challenge.Scheme == TokenTypes.Bearer));
    }
}
