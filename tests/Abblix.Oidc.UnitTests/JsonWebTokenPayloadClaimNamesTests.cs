// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Xunit;

namespace Abblix.Oidc.UnitTests;

/// <summary>
/// Each claim property writes the claim under its registered name, which a test that writes and reads through the
/// same property cannot show: a wrong name survives the round trip.
/// </summary>
public class JsonWebTokenPayloadClaimNamesTests
{
    public static TheoryData<string, Action<JsonWebTokenPayload>> Claims => new()
    {
        { IanaClaimTypes.Sid, p => p.SessionId = "s" },
        { IanaClaimTypes.ClientId, p => p.ClientId = "c" },
        { IanaClaimTypes.Azp, p => p.AuthorizedParty = "c" },
        { IanaClaimTypes.Scope, p => p.Scope = ["openid"] },
        { OidcClaimTypes.IdentityProvider, p => p.IdentityProvider = "local" },
        { OidcClaimTypes.GrantId, p => p.GrantId = "g" },
        { IanaClaimTypes.AuthTime, p => p.AuthenticationTime = DateTimeOffset.UnixEpoch },
        { IanaClaimTypes.Nonce, p => p.Nonce = "n" },
        { IanaClaimTypes.AtHash, p => p.AccessTokenHash = "h" },
        { IanaClaimTypes.CHash, p => p.CodeHash = "h" },
        { IanaClaimTypes.Amr, p => p.AuthenticationMethodReferences = ["pwd"] },
        { IanaClaimTypes.Acr, p => p.AuthContextClassRef = "loa" },
        { IanaClaimTypes.Email, p => p.Email = "e@example.com" },
        { IanaClaimTypes.EmailVerified, p => p.EmailVerified = true },
        { IanaClaimTypes.Htm, p => p.DPoPHttpMethod = "POST" },
        { IanaClaimTypes.Htu, p => p.DPoPHttpUri = "https://example.com/token" },
        { IanaClaimTypes.Ath, p => p.DPoPAccessTokenHash = "h" },
        {
            IanaClaimTypes.AuthorizationDetails,
            p => p.AuthorizationDetails = [new AuthorizationDetail(new JsonObject { ["type"] = "t" })]
        },
    };

    [Theory]
    [MemberData(nameof(Claims))]
    public void TheClaim_IsWrittenUnderItsRegisteredName(string name, Action<JsonWebTokenPayload> set)
    {
        var payload = new JsonWebTokenPayload(new JsonObject());

        set(payload);

        Assert.Equal([name], payload.Json.Select(claim => claim.Key));
    }
}
