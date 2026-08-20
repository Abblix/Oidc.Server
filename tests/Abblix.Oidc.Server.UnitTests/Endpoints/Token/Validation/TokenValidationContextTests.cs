// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Endpoints.Token.Validation;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Endpoints.Token.Validation;

/// <summary>
/// The token pipeline's per-request context, and the two properties the pipeline fills in as it goes.
/// </summary>
public class TokenValidationContextTests
{
    private static TokenValidationContext Unfilled() => new(new TokenRequest(), new ClientRequest());

    /// <summary>
    /// Reading a grant that the pipeline has not established yet is a loud failure naming the property,
    /// not a quiet null.
    /// </summary>
    /// <remarks>
    /// The property is what the sender-constraining checks read to learn whether the grant was issued
    /// bound to a proof key (RFC 9449) or to a client certificate (RFC 8705). While it was declared with a
    /// null-forgiving initialiser those checks reached it through a null-conditional, so an unset grant did
    /// not fail - it read as "nothing was committed", which is precisely the answer that lets a bound token
    /// be redeemed without the key or certificate it was bound to.
    /// The reordering that produces an unset grant is available to a host: the validator family is editable
    /// through the supported composition API, and its ordering constraint is not written down anywhere the
    /// editor would see it. That makes this the difference between a loud misconfiguration and a silent
    /// hole, which is the whole point of asserting it here.
    /// </remarks>
    [Fact]
    public void AnUnsetAuthorizedGrantIsRefusedByName()
    {
        var context = Unfilled();

        var error = Assert.Throws<InvalidOperationException>(() => context.AuthorizedGrant);
        Assert.Contains(nameof(TokenValidationContext.AuthorizedGrant), error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Its neighbour behaves the same way, which is the point: two properties of one context, filled by one
    /// pipeline, expressing the same fact the same way.
    /// </summary>
    [Fact]
    public void AnUnsetClientInfoIsRefusedByName()
    {
        var context = Unfilled();

        var error = Assert.Throws<InvalidOperationException>(() => context.ClientInfo);
        Assert.Contains(nameof(TokenValidationContext.ClientInfo), error.Message, StringComparison.Ordinal);
    }
}
