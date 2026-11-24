// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientAuthentication;

/// <summary>
/// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 3.2.4: the Basic challenge is owed to a request whose client "attempted
/// to authenticate via the Authorization request header field" with HTTP Basic, the server's one scheme for clients;
/// "Client authentication methods that do not use an HTTP authentication scheme have no corresponding challenge". The
/// answer reads the request alone, so it tells nothing of the client the request names.
/// </summary>
public class BasicChallengeTests
{
    private static readonly string BasicCredentials =
        Convert.ToBase64String(Encoding.UTF8.GetBytes($"{TestConstants.DefaultClientId}:wrong"));

    [Theory]
    [InlineData(TokenTypes.Basic, true)]
    [InlineData("basic", true)]
    [InlineData(TokenTypes.Bearer, false)]
    [InlineData(null, false)]
    public void IsOwed_ForARequestUsingBasic(string? scheme, bool expected)
    {
        var request = new ClientRequest
        {
            ClientId = TestConstants.DefaultClientId,
            AuthorizationHeaderLines = scheme is null ? null : [$"{scheme} {BasicCredentials}"],
        };

        Assert.Equal(expected, BasicChallenge.IsOwed(request));
        Assert.Equal(expected, BasicChallenge.InvalidClient(request, "refused").BasicChallengeOwed);
        Assert.Equal(ErrorCodes.InvalidClient, BasicChallenge.InvalidClient(request, "refused").Error);
    }
}
