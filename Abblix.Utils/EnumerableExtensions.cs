// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

namespace Abblix.Utils;

/// <summary>
/// Provides extension methods for IEnumerable&lt;T&gt; for common operations.
/// </summary>
public static class EnumerableExtensions
{
	/// <summary>
	/// Returns the original sequence, or an empty sequence if the original is null.
	/// </summary>
	/// <typeparam name="T">The type of elements in the sequence.</typeparam>
	/// <param name="value">The sequence to return or an empty sequence if this is null.</param>
	/// <returns>The original sequence or an empty sequence.</returns>
	public static IEnumerable<T> OrEmpty<T>(this IEnumerable<T>? value)
		=> value ?? Enumerable.Empty<T>();

	/// <summary>
	/// Traverses a hierarchy upwards, starting from a specific item and moving to its parent, grandparent, etc., as determined by a parent selector function.
	/// </summary>
	/// <typeparam name="T">The type of elements in the hierarchy.</typeparam>
	/// <param name="item">The starting item in the hierarchy.</param>
	/// <param name="parentSelector">A function that returns the parent of a given item.</param>
	/// <returns>An IEnumerable&lt;T&gt; representing the path from the item upwards in the hierarchy.</returns>
	public static IEnumerable<T> TravelUp<T>(this T item, Func<T, T?> parentSelector)
	{
		for (var current = item; current != null; )
		{
			yield return current;

			var parent = parentSelector(current);

			if (ReferenceEquals(parent, current))
				yield break;

			current = parent;
		}
	}

	/// <summary>
	/// Flattens a tree structure into a flat sequence using breadth-first traversal.
	/// </summary>
	/// <typeparam name="T">The type of elements in the tree.</typeparam>
	/// <param name="input">The sequence of root elements.</param>
	/// <param name="childrenSelector">A function to retrieve the children of an element.</param>
	/// <returns>A flattened sequence of all elements in the tree.</returns>
	public static IEnumerable<T> FlattenTree<T>(this IEnumerable<T> input, Func<T, IEnumerable<T>> childrenSelector)
	{
		var queue = new Queue<T>();
		queue.EnqueueAll(input);
		return queue.FlattenTreeImpl(childrenSelector);
	}

	/// <summary>
	/// Flattens a tree structure starting from a single root element into a flat sequence using breadth-first traversal.
	/// </summary>
	/// <typeparam name="T">The type of elements in the tree.</typeparam>
	/// <param name="root">The root element of the tree.</param>
	/// <param name="childrenSelector">A function to retrieve the children of an element.</param>
	/// <returns>A flattened sequence of all elements in the tree.</returns>
	public static IEnumerable<T> FlattenTree<T>(this T root, Func<T, IEnumerable<T>> childrenSelector)
	{
		var queue = new Queue<T>();
		queue.Enqueue(root);
		return queue.FlattenTreeImpl(childrenSelector);
	}

	private static IEnumerable<T> FlattenTreeImpl<T>(this Queue<T> queue, Func<T, IEnumerable<T>> childrenSelector)
	{
		while (0 < queue.Count)
		{
			var item = queue.Dequeue();
			yield return item;
			queue.EnqueueAll(childrenSelector(item));
		}
	}

	private static void EnqueueAll<T>(this Queue<T> queue, IEnumerable<T> input)
	{
		foreach (var item in input.OrEmpty())
		{
			queue.Enqueue(item);
		}
	}
}
