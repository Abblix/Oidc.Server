// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
