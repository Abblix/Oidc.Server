// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections;
using System.Collections.Concurrent;

namespace Abblix.Utils.Collections;

/// <summary>
/// A set that several threads may add to and enumerate at the same time, losing neither what is already stored
/// nor what is being added.
/// </summary>
/// <remarks>
/// The .NET base class library ships no concurrent set, so the choice is between a <see cref="HashSet{T}"/>
/// under a lock and the keys of a <see cref="ConcurrentDictionary{TKey,TValue}"/>, which are exactly a
/// concurrent set with a value nobody reads. The dictionary wins on two counts.
///
/// Its <c>TryAdd</c> is an atomic test-and-add that also reports which caller performed the addition. That is
/// the operation the defect needed: <c>if (!Contains) Add</c> is two operations with a window between them, and
/// a lock closes the window only for as long as every caller remembers to take it, whereas here the guarantee
/// belongs to the type.
///
/// And its <c>Keys</c> property is documented to return "a copy of all the keys", not "kept in sync" with the
/// dictionary. That promise is what makes this usable from an <c>async</c> loop: a reader holding a lock cannot
/// <c>await</c> inside the loop, so any lock-based set would force the caller to copy first - and a copy is
/// what this returns to begin with. A reader iterating while a writer adds therefore neither throws
/// <see cref="InvalidOperationException"/> nor loses an element that was already there.
///
/// The alternative considered was an <c>ImmutableHashSet</c> field updated by
/// <see cref="System.Threading.Interlocked.CompareExchange{T}(ref T, T, T)"/>: correct, and lock-free, but it
/// allocates a new version of the set per addition and spins a retry loop under contention, for no gain over
/// this. The cost of what is here instead is a placeholder byte per element and a <see cref="Count"/> that
/// takes every segment lock - both irrelevant at the sizes this holds.
/// </remarks>
/// <typeparam name="T">The element type. Uses the type's default equality comparer.</typeparam>
public sealed class ConcurrentSet<T> : ICollection<T> where T : notnull
{
    /// <summary>Creates an empty set.</summary>
    public ConcurrentSet()
    {
    }

    /// <summary>Creates a set containing the distinct elements of <paramref name="items"/>.</summary>
    public ConcurrentSet(IEnumerable<T> items)
    {
        foreach (var item in items)
            Add(item);
    }

    // The value is a placeholder: the dictionary's keys are the set, and nothing ever reads the value.
    private readonly ConcurrentDictionary<T, byte> _items = new();

    /// <summary>
    /// Adds an item if it is not already present. Returns whether this call is the one that added it, which
    /// lets a caller act on the transition (persist, notify) exactly once even under concurrency - something
    /// <see cref="ICollection{T}.Add"/> cannot express, since it returns nothing.
    /// </summary>
    public bool TryAdd(T item) => _items.TryAdd(item, 0);

    /// <inheritdoc />
    public void Add(T item) => TryAdd(item);

    /// <inheritdoc />
    public bool Remove(T item) => _items.TryRemove(item, out _);

    /// <inheritdoc />
    public void Clear() => _items.Clear();

    /// <inheritdoc />
    public bool Contains(T item) => _items.ContainsKey(item);

    /// <inheritdoc />
    public int Count => _items.Count;

    /// <inheritdoc />
    public bool IsReadOnly => false;

    /// <inheritdoc />
    public void CopyTo(T[] array, int arrayIndex) => _items.Keys.CopyTo(array, arrayIndex);

    /// <summary>
    /// Enumerates a snapshot taken when enumeration begins, so what a reader sees does not depend on what a
    /// writer does while it reads.
    /// </summary>
    /// <remarks>
    /// Goes through <c>Keys</c> deliberately, and not through the dictionary's own enumerator: the latter is
    /// documented as "safe to use concurrently with reads and writes ... however it does not represent a
    /// moment-in-time snapshot", so it would show some later additions and not others depending on timing.
    /// Neither form can throw, so this is not about safety - it is about a caller that enumerates across
    /// <c>await</c> points getting a defined answer rather than a race-dependent one. Do not "simplify" this to
    /// the dictionary's enumerator to save the copy.
    /// </remarks>
    public IEnumerator<T> GetEnumerator() => _items.Keys.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
