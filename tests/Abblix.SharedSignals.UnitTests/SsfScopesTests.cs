// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// The one-way inclusion the CAEP Interoperability Profile states between the two scopes.
/// </summary>
/// <remarks>
/// Section 2.7.3: "The ssf.manage scope includes all ssf.read permissions and additionally allows Create
/// Stream, Delete Stream, and Stream Verification operations." One direction only, and the direction is
/// the whole content of this function - a symmetric check would let a read-only receiver delete a stream.
/// </remarks>
public class SsfScopesTests
{
    [Fact]
    public void Manage_SatisfiesRead()
        => Assert.True(SsfScopes.Satisfies([SsfScopes.Manage], SsfScopes.Read));

    /// <summary>
    /// The direction that must NOT hold, and the reason the check is not a set intersection.
    /// </summary>
    [Fact]
    public void Read_DoesNotSatisfyManage()
        => Assert.False(SsfScopes.Satisfies([SsfScopes.Read], SsfScopes.Manage));

    [Theory]
    [InlineData(SsfScopes.Read)]
    [InlineData(SsfScopes.Manage)]
    public void AScope_SatisfiesItself(string scope)
        => Assert.True(SsfScopes.Satisfies([scope], scope));

    /// <summary>
    /// A token carrying unrelated scopes alongside the right one still passes: receivers hold tokens
    /// issued for more than this API.
    /// </summary>
    [Fact]
    public void UnrelatedScopesAlongside_DoNotInterfere()
        => Assert.True(SsfScopes.Satisfies(["openid", "profile", SsfScopes.Manage], SsfScopes.Read));

    [Theory]
    [InlineData(SsfScopes.Read)]
    [InlineData(SsfScopes.Manage)]
    public void NothingGranted_SatisfiesNothing(string required)
        => Assert.False(SsfScopes.Satisfies([], required));

    /// <summary>
    /// The comparison is exact. A scope that merely starts with the right characters is a different
    /// scope, and the profile reserves the whole <c>ssf.</c> prefix precisely so that neighbours exist.
    /// </summary>
    [Theory]
    [InlineData("ssf")]
    [InlineData("ssf.rea")]
    [InlineData("ssf.read.all")]
    [InlineData("SSF.READ")]
    public void ANeighbouringString_IsNotTheScope(string granted)
        => Assert.False(SsfScopes.Satisfies([granted], SsfScopes.Read));
}
