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
using Abblix.Oidc.Server.Features.DPoP;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DPoP;

/// <summary>
/// A DPoP proof's <c>htu</c> claim is told apart as absent, not an absolute http or https URI, or another URI than the request's
/// (RFC 9449 section 4.3), each with a reason of its own.
/// </summary>
public class ProofBindingClaimsTests
{
    private static readonly Uri RequestUri = new("https://auth.example.com/token");

    [Fact]
    public void AnAbsentClaim_IsMissing()
        => Assert.Equal(ProofErrorReasons.HttpUriMissing, ProofBindingClaims.HttpUri(Payload(null), RequestUri)?.Reason);

    [Theory]
    [InlineData("not a uri")]
    [InlineData("/token")]
    [InlineData("file:///token")]
    [InlineData("wss://auth.example.com/token")]
    public void AClaimThatIsNoHttpUri_IsInvalid(string htu)
        => Assert.Equal(ProofErrorReasons.HttpUriInvalid, ProofBindingClaims.HttpUri(Payload(htu), RequestUri)?.Reason);

    [Fact]
    public void AnotherUri_IsAMismatch()
        => Assert.Equal(
            ProofErrorReasons.HttpUriMismatch,
            ProofBindingClaims.HttpUri(Payload("https://auth.example.com/other"), RequestUri)?.Reason);

    [Fact]
    public void TheRequestUri_IsAccepted()
        => Assert.Null(ProofBindingClaims.HttpUri(Payload(RequestUri.OriginalString), RequestUri));

    private static JsonWebTokenPayload Payload(string? htu)
    {
        var json = new JsonObject();
        if (htu is not null)
            json[IanaClaimTypes.Htu] = htu;

        return new JsonWebTokenPayload(json);
    }
}
