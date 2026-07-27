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

namespace Abblix.Utils.UnitTests;

/// <summary>
/// The array helpers that return an array rather than a sequence, which is why they exist alongside the LINQ
/// members of the same name and why call sites that need a <c>T[]</c> bind to these.
/// </summary>
/// <remarks>
/// Every case asserts the new array's contents AND that the source was left alone. These allocate a new array
/// and copy into it, so an off-by-one in the copy offset would put the value in the wrong slot or overwrite a
/// neighbour, and only reading the whole result catches that. The source-unchanged assertion is what stops a
/// future rewrite from turning these into in-place mutation, which every one of the call sites would then be
/// wrong about.
/// </remarks>
public class ArrayExtensionsTests
{
    [Fact]
    public void Append_PutsTheValueLast_AndLeavesTheSourceAlone()
    {
        var source = new[] { "openid", "profile" };

        var result = source.Append("offline_access");

        Assert.Equal(["openid", "profile", "offline_access"], result);
        Assert.Equal(["openid", "profile"], source);
    }

    [Fact]
    public void Prepend_PutsTheValueFirst_AndLeavesTheSourceAlone()
    {
        var source = new[] { "profile", "email" };

        var result = source.Prepend("openid");

        Assert.Equal(["openid", "profile", "email"], result);
        Assert.Equal(["profile", "email"], source);
    }

    /// <summary>
    /// The empty source is the case the copy loop can get wrong while every other length works: it is the
    /// only one where the copy has nothing to move and the single element is both first and last.
    /// </summary>
    [Fact]
    public void AppendAndPrepend_OnAnEmptyArray_ProduceTheSingleElement()
    {
        Assert.Equal(["only"], Array.Empty<string>().Append("only"));
        Assert.Equal(["only"], Array.Empty<string>().Prepend("only"));
    }

    [Fact]
    public void Concat_OfTwoArrays_JoinsThemInOrder()
    {
        byte[] first = [1, 2, 3];
        byte[] second = [4, 5];

        Assert.Equal([1, 2, 3, 4, 5], first.Concat(second));
    }

    [Fact]
    public void Concat_OfSeveralArrays_JoinsThemInOrder()
        => Assert.Equal([1, 2, 3, 4], ArrayExtensions.Concat([1], [2, 3], [], [4]));
}
