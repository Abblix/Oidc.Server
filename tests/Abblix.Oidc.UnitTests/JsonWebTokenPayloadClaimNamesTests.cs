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
/// <remarks>
/// The expected names are written as the registries spell them rather than through the claim constants: the
/// property reads those same constants, so a misspelled value would sit on both sides of the comparison and pass.
/// </remarks>
public class JsonWebTokenPayloadClaimNamesTests
{
    public static TheoryData<string, Action<JsonWebTokenPayload>> Claims => new()
    {
        { "sid", p => p.SessionId = "s" },
        { "client_id", p => p.ClientId = "c" },
        { "azp", p => p.AuthorizedParty = "c" },
        { "scope", p => p.Scope = ["openid"] },
        { "idp", p => p.IdentityProvider = "local" },
        { "grant_id", p => p.GrantId = "g" },
        { "auth_time", p => p.AuthenticationTime = DateTimeOffset.UnixEpoch },
        { "nonce", p => p.Nonce = "n" },
        { "at_hash", p => p.AccessTokenHash = "h" },
        { "c_hash", p => p.CodeHash = "h" },
        { "amr", p => p.AuthenticationMethodReferences = ["pwd"] },
        { "acr", p => p.AuthContextClassRef = "loa" },
        { "email", p => p.Email = "e@example.com" },
        { "email_verified", p => p.EmailVerified = true },
        { "htm", p => p.DPoPHttpMethod = "POST" },
        { "htu", p => p.DPoPHttpUri = "https://example.com/token" },
        { "ath", p => p.DPoPAccessTokenHash = "h" },
        {
            "authorization_details",
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
