// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections;

namespace Abblix.Oidc.Server.SourceGenerators;

/// <summary>
/// An immutable array with value equality, required by the incremental generator pipeline:
/// the driver caches a step's output only when it compares equal to the previous run, and
/// the default array equality is referential.
/// </summary>
internal readonly struct EquatableArray<T>(T[] items) : IEquatable<EquatableArray<T>>, IEnumerable<T>
	where T : IEquatable<T>
{
	private readonly T[]? _items = items;

	public int Length => _items?.Length ?? 0;

	public bool Equals(EquatableArray<T> other)
	{
		var left = _items ?? [];
		var right = other._items ?? [];

		if (left.Length != right.Length)
			return false;

		for (var i = 0; i < left.Length; i++)
		{
			if (!left[i].Equals(right[i]))
				return false;
		}

		return true;
	}

	public override bool Equals(object? obj)
		=> obj is EquatableArray<T> other && Equals(other);

	public override int GetHashCode()
	{
		if (_items == null)
			return 0;

		var hashCode = 17;
		foreach (var item in _items)
		{
			hashCode = unchecked(hashCode * 31 + item.GetHashCode());
		}

		return hashCode;
	}

	public IEnumerator<T> GetEnumerator() => ((IEnumerable<T>)(_items ?? [])).GetEnumerator();

	IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
