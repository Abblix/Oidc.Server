// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Tests the accessors for the claims that bind an ID token to what was issued alongside it.
/// </summary>
/// <remarks>
/// These two claims are how a relying party detects a substitution: <c>at_hash</c> catches an access token
/// swapped for another, <c>c_hash</c> catches an authorization code swapped in the front channel. Reading
/// them through a typed accessor rather than a string literal is what keeps a typo from silently turning a
/// check into a no-op, since a misspelled claim name simply reads as absent.
/// </remarks>
public class TokenBindingClaimsTests
{
    private const string AccessTokenHashValue = "xsZZrUssMXjL3FBlzoSh2g";
    private const string CodeHashValue = "LDktKdoQak3Pk0cnXxCltA";

    /// <summary>
    /// The access-token hash round-trips through the accessor.
    /// </summary>
    [Fact]
    public void AccessTokenHashRoundTrips()
    {
        var payload = new JsonWebTokenPayload(new JsonObject()) { AccessTokenHash = AccessTokenHashValue };

        Assert.Equal(AccessTokenHashValue, payload.AccessTokenHash);
    }

    /// <summary>
    /// The code hash round-trips through the accessor.
    /// </summary>
    [Fact]
    public void CodeHashRoundTrips()
    {
        var payload = new JsonWebTokenPayload(new JsonObject()) { CodeHash = CodeHashValue };

        Assert.Equal(CodeHashValue, payload.CodeHash);
    }

    /// <summary>
    /// The accessors write the wire names the specification defines, not the property names. A relying party
    /// reads what the provider wrote, so the two have to agree exactly.
    /// </summary>
    [Fact]
    public void TheAccessorsUseTheWireNames()
    {
        var json = new JsonObject();

        _ = new JsonWebTokenPayload(json)
        {
            AccessTokenHash = AccessTokenHashValue,
            CodeHash = CodeHashValue,
        };

        Assert.Equal(AccessTokenHashValue, (string?)json[IanaClaimTypes.AtHash]);
        Assert.Equal(CodeHashValue, (string?)json[IanaClaimTypes.CHash]);
    }

    /// <summary>
    /// A token carrying neither claim reads as absent rather than empty, so a caller can tell "the provider
    /// did not bind this" from "the provider bound it to nothing".
    /// </summary>
    [Fact]
    public void AbsentClaimsReadAsNull()
    {
        var payload = new JsonWebTokenPayload(new JsonObject());

        Assert.Null(payload.AccessTokenHash);
        Assert.Null(payload.CodeHash);
    }

    /// <summary>
    /// The two claims are independent: writing one leaves the other absent. They are set at different points
    /// of different flows, so a payload carrying only one of them is normal.
    /// </summary>
    [Fact]
    public void TheClaimsAreIndependent()
    {
        var payload = new JsonWebTokenPayload(new JsonObject()) { AccessTokenHash = AccessTokenHashValue };

        Assert.Equal(AccessTokenHashValue, payload.AccessTokenHash);
        Assert.Null(payload.CodeHash);
    }
}
