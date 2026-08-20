// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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

        // Single materialization upfront...
        Assert.Equal(1, enumerationCount);
        // ...and replay-many afterwards: subsequent enumerations do not
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
