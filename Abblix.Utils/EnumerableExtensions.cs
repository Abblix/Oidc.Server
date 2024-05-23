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
	/// Traverses a hierarchy upwards, starting from a specific item and moving to its parent, grandparent, etc.,
	/// as determined by a parent selector function.
	/// </summary>
	/// <typeparam name="T">The type of elements in the hierarchy.</typeparam>
	/// <param name="item">The starting item in the hierarchy.</param>
	/// <param name="parentSelector">A function that returns the parent of a given item.</param>
	/// <returns>An IEnumerable&lt;T&gt; representing the path from the item upwards in the hierarchy.</returns>
	public static IEnumerable<T> TravelUp<T>(this T item, Func<T, T?> parentSelector)
		where T: class
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
	public static IEnumerable<T> FlattenTree<T>(this IEnumerable<T>? input, Func<T, IEnumerable<T>> childrenSelector)
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

	/// <summary>
	/// Enqueues all elements from a specified collection into the given queue.
	/// </summary>
	/// <typeparam name="T">The type of elements contained in the queue and the enumerable collection.</typeparam>
	/// <param name="queue">The queue into which elements will be enqueued.</param>
	/// <param name="input">The collection of elements to enqueue. If the collection is null, no action is taken.
	/// </param>
	public static void EnqueueAll<T>(this Queue<T> queue, IEnumerable<T>? input)
	{
		if (input == null)
			return;

		foreach (var item in input)
		{
			queue.Enqueue(item);
		}
	}
}
