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
		=> value ?? [];

	/// <summary>
	/// Forces a sequence to be evaluated once and returns the result as a non-lazy
	/// <see cref="IReadOnlyCollection{T}"/> that callers can iterate any number of times.
	/// Use at any site that needs to enumerate the same <see cref="IEnumerable{T}"/> more than once
	/// (cost estimate + actual call, log + record, etc.) — a lazy LINQ pipeline or an iterator
	/// method passed by an upstream caller would otherwise re-execute its source per enumeration.
	/// </summary>
	/// <remarks>
	/// Skips the allocation when <paramref name="source"/> is already a concrete collection
	/// (<c>T[]</c>, <c>List&lt;T&gt;</c>, <c>HashSet&lt;T&gt;</c>, etc.) — only lazy /
	/// iterator-method sources pay for a one-shot copy.
	/// </remarks>
	/// <typeparam name="T">The type of elements in the sequence.</typeparam>
	/// <param name="source">The sequence to materialize.</param>
	/// <returns>A non-lazy collection holding all elements of <paramref name="source"/>.</returns>
	public static IReadOnlyCollection<T> Materialize<T>(this IEnumerable<T> source)
		=> source as IReadOnlyCollection<T> ?? [..source];

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
		var current = item;
		while (current != null)
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
