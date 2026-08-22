// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Storages;

/// <summary>
/// The storage keys are a wire format: a running deployment holds records under the names this factory
/// produced yesterday, so changing one orphans them rather than renaming them.
/// </summary>
/// <remarks>
/// The revocation cutoff is the one where that costs most. Orphaning it does not lose data anybody notices -
/// it quietly un-revokes every suspended account and every ended session on deploy, with nothing failing.
/// </remarks>
public class EntityStorageKeyFactoryTests
{
    private static readonly IEntityStorageKeyFactory Factory = new EntityStorageKeyFactory();

    [Theory]
    [InlineData(RevocationScope.Subject, "Abblix.Oidc.Server:Revoked:subject:user_42")]
    [InlineData(RevocationScope.Session, "Abblix.Oidc.Server:Revoked:session:user_42")]
    public void RevocationCutoffKey_HasTheNameLiveRecordsAreHeldUnder(RevocationScope scope, string expected)
    {
        Assert.Equal(expected, Factory.RevocationCutoffKey(scope, "user_42"));
    }

    /// <summary>
    /// Every scope has a key, so a member added later fails here rather than at the throw inside the factory -
    /// which a request would reach first, as a fault in the middle of validating somebody's token.
    /// </summary>
    [Fact]
    public void RevocationCutoffKey_CoversEveryScope()
    {
        var scopes = Enum.GetValues<RevocationScope>();
        Assert.NotEmpty(scopes);

        var keys = scopes.Select(scope => Factory.RevocationCutoffKey(scope, "user_42")).ToArray();

        // Distinct, because two scopes sharing a name would let a session revocation refuse a subject's
        // tokens, or the reverse - a collision no test of a single scope can see.
        Assert.Equal(keys.Length, keys.Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>
    /// A scope the factory does not know is refused loudly. Reading it as any existing scope would silently
    /// revoke the wrong principal.
    /// </summary>
    [Fact]
    public void RevocationCutoffKey_RefusesAnUnknownScope()
    {
        var unknown = (RevocationScope)int.MaxValue;

        Assert.Throws<ArgumentOutOfRangeException>(() => Factory.RevocationCutoffKey(unknown, "user_42"));
    }
}
