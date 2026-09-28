// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Common;

/// <summary>
/// The one rule every place judging a session's authentication level shares.
/// </summary>
public class AuthenticationLevelsTests
{
    private const string Strong = "urn:example:acr:strong";
    private const string Weak = "urn:example:acr:weak";

    /// <summary>
    /// A named level is met only by a session holding it; nothing named accepts any session; and a session
    /// recording no level, or an empty one, meets no named level - even an empty one somebody named.
    /// </summary>
    [Theory]
    [InlineData(new string[0], null, true)]
    [InlineData(new string[0], Weak, true)]
    [InlineData(new[] { Strong }, Strong, true)]
    [InlineData(new[] { Strong }, Weak, false)]
    [InlineData(new[] { Strong }, null, false)]
    [InlineData(new[] { "" }, "", false)]
    public void ASessionMeetsOnlyALevelItHolds(string[] accepted, string? level, bool meets)
        => Assert.Equal(meets, AuthenticationLevels.Accept(accepted, level));

    /// <summary>
    /// The levels recorded on a decoupled request decide, whatever its grant's claims say; a request stored
    /// before they were recorded is judged by its grant's claims instead.
    /// </summary>
    [Theory]
    [InlineData(new[] { Strong }, false, false)]
    [InlineData(new string[0], true, true)]
    [InlineData(null, true, false)]
    [InlineData(null, false, true)]
    public void TheRecordedLevelsDecide_AndTheGrantAnswersForAnOlderRequest(
        string[]? recorded, bool grantRequiresStrong, bool meets)
    {
        var claims = grantRequiresStrong
            ? new RequestedClaims
            {
                IdToken = new() { [IanaClaimTypes.Acr] = new RequestedClaimDetails { Essential = true, Values = [Strong] } },
            }
            : null;

        Assert.Equal(meets, AuthenticationLevels.Accept(recorded, claims, Weak));
    }
}
