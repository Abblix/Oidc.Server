// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Tokens.Revocation;

/// <summary>
/// No pair of a client and an end user shares a principal with another pair, whatever characters the two hold:
/// a shared principal would let withdrawing consent from one client revoke another pair's tokens.
/// </summary>
public class RevocationPrincipalTests
{
    [Theory]
    [InlineData("a:b", "c", "a", "b:c")]
    [InlineData("1:a", "b", "1", "a:b")]
    [InlineData("client", "user", "client", "user ")]
    public void TwoPairs_HaveTwoPrincipals(string firstClient, string firstSubject, string secondClient, string secondSubject)
        => Assert.NotEqual(
            RevocationPrincipal.ClientSubject(firstClient, firstSubject),
            RevocationPrincipal.ClientSubject(secondClient, secondSubject));
}
