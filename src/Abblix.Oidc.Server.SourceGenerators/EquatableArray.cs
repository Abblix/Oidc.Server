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
