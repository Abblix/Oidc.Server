// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.UserAuthentication;

/// <summary>
/// What a session's additional claims may and may not write into a token.
/// </summary>
/// <remarks>
/// A host fills the additional claims, often by copying what an upstream identity provider sent, so they carry
/// names the token already uses. The token services write the token's own claims before the session, so an
/// additional claim written over them would decide who the token is about and how long it lives.
/// </remarks>
public class AuthSessionExtensionsTests
{
    private static readonly DateTimeOffset AuthenticatedAt = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
    private static readonly DateTimeOffset IssuedAt = DateTimeOffset.FromUnixTimeSeconds(1_700_000_100);

    private static AuthSession Session(JsonObject additionalClaims) => new(
        "alice", "alice-session", AuthenticatedAt, "local")
    {
        AdditionalClaims = additionalClaims,
    };

    private static JsonWebTokenPayload IssuedPayload() => new(new JsonObject())
    {
        JwtId = "token-id",
        IssuedAt = IssuedAt,
        ExpiresAt = IssuedAt + TimeSpan.FromMinutes(5),
        Issuer = TestConstants.DefaultIssuer.OriginalString,
    };

    [Fact]
    public void Additional_claims_named_like_session_claims_do_not_replace_the_session()
    {
        var payload = IssuedPayload();

        Session(new JsonObject
        {
            [JwtClaimTypes.Subject] = "mallory",
            [JwtClaimTypes.SessionId] = "forged-session",
            [JwtClaimTypes.AuthenticationTime] = 1,
        }).ApplyTo(payload);

        Assert.Equal(("alice", "alice-session", AuthenticatedAt),
            (payload.Subject, payload.SessionId, payload.AuthenticationTime));
    }

    [Fact]
    public void Additional_claims_do_not_replace_what_the_token_already_carries()
    {
        var payload = IssuedPayload();

        Session(new JsonObject
        {
            [JwtClaimTypes.ExpiresAt] = 4_102_444_800,
            [JwtClaimTypes.Issuer] = "https://forged.example.com",
            [JwtClaimTypes.JwtId] = "forged-id",
        }).ApplyTo(payload);

        Assert.Equal(IssuedAt + TimeSpan.FromMinutes(5), payload.ExpiresAt);
        Assert.Equal(TestConstants.DefaultIssuer.OriginalString, payload.Issuer);
        Assert.Equal("token-id", payload.JwtId);
    }

    /// <summary>
    /// A session without an email says nothing about the email, and an additional claim does not say it instead.
    /// </summary>
    [Fact]
    public void Additional_claims_named_like_a_session_claim_the_session_leaves_empty_are_not_written()
    {
        var payload = IssuedPayload();

        Session(new JsonObject { [JwtClaimTypes.Email] = "mallory@example.com" }).ApplyTo(payload);

        Assert.Null(payload.Email);
    }

    /// <summary>
    /// A claim a token service wrote that has no session counterpart, like the refresh token's grant id, is kept
    /// for being in the token, not for being on a list.
    /// </summary>
    [Fact]
    public void Additional_claims_do_not_replace_a_claim_only_the_token_service_knows()
    {
        var payload = IssuedPayload();
        payload.Json["gid"] = "grant";

        Session(new JsonObject { ["gid"] = "forged-grant" }).ApplyTo(payload);

        Assert.Equal("grant", payload.Json["gid"]!.GetValue<string>());
    }

    [Fact]
    public void Additional_claims_of_their_own_reach_the_token()
    {
        var payload = IssuedPayload();

        Session(new JsonObject { ["tenant"] = "acme" }).ApplyTo(payload);

        Assert.Equal("acme", payload.Json["tenant"]!.GetValue<string>());
    }
}
