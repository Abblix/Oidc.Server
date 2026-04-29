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

using System.Collections.Generic;
using System.Linq;
using Abblix.Utils;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Utils;

public class EnumerableExtensionsTests
{
    [Fact]
    public void Materialize_ArraySource_ReturnsSameInstance_NoCopy()
    {
        var source = new[] { 1, 2, 3 };

        var materialized = source.Materialize();

        Assert.Same(source, materialized);
    }

    [Fact]
    public void Materialize_ListSource_ReturnsSameInstance_NoCopy()
    {
        var source = new List<int> { 1, 2, 3 };

        var materialized = source.Materialize();

        Assert.Same(source, materialized);
    }

    [Fact]
    public void Materialize_HashSetSource_ReturnsSameInstance_NoCopy()
    {
        var source = new HashSet<int> { 1, 2, 3 };

        var materialized = source.Materialize();

        Assert.Same(source, materialized);
    }

    [Fact]
    public void Materialize_LazyLinqSource_EvaluatesOnce_AndReturnsConcreteCollection()
    {
        var enumerationCount = 0;
        IEnumerable<int> Lazy()
        {
            enumerationCount++;
            yield return 1;
            yield return 2;
            yield return 3;
        }

        var materialized = Lazy().Materialize();

        // Single materialization upfront…
        Assert.Equal(1, enumerationCount);
        // …and replay-many afterwards: subsequent enumerations do not
        // re-execute the source iterator.
        Assert.Equal([1, 2, 3], materialized);
        Assert.Equal([1, 2, 3], materialized);
        Assert.Equal(1, enumerationCount);
    }

    [Fact]
    public void Materialize_LazyLinqSource_PreservesOrder()
    {
        var source = Enumerable.Range(1, 5).Where(x => x % 2 == 1);

        var materialized = source.Materialize();

        Assert.Equal([1, 3, 5], materialized);
    }

    [Fact]
    public void Materialize_EmptySource_ReturnsEmptyCollection()
    {
        var materialized = Enumerable.Empty<int>().Materialize();

        Assert.Empty(materialized);
    }
}
