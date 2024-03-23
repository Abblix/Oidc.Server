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
/// Provides extension methods for working with asynchronous enumerable sequences.
/// </summary>
public static class AsyncEnumerableExtensions
{
	/// <summary>
	/// Prepends a value to the beginning of an asynchronous sequence.
	/// </summary>
	/// <typeparam name="T">The type of elements in the sequence.</typeparam>
	/// <param name="values">The asynchronous sequence.</param>
	/// <param name="firstValue">The value to prepend.</param>
	/// <returns>An IAsyncEnumerable sequence that starts with the specified value followed by the original sequence.</returns>
	public static async IAsyncEnumerable<T> PrependAsync<T>(this IAsyncEnumerable<T> values, T firstValue)
	{
		yield return firstValue;

		await foreach (var value in values)
		{
			yield return value;
		}
	}


	/// <summary>
	/// Appends a value to the end of an asynchronous sequence.
	/// </summary>
	/// <typeparam name="T">The type of elements in the sequence.</typeparam>
	/// <param name="values">The asynchronous sequence.</param>
	/// <param name="lastValue">The value to append.</param>
	/// <returns>An IAsyncEnumerable sequence that ends with the specified value after the original sequence.</returns>
	public static async IAsyncEnumerable<T> AppendAsync<T>(this IAsyncEnumerable<T> values, T lastValue)
	{
		await foreach (var value in values)
		{
			yield return value;
		}

		yield return lastValue;
	}

	/// <summary>
	/// Filters an asynchronous sequence to only include distinct elements.
	/// </summary>
	/// <typeparam name="T">The type of elements in the sequence.</typeparam>
	/// <param name="values">The asynchronous sequence.</param>
	/// <returns>An IAsyncEnumerable sequence that contains distinct elements from the original sequence.</returns>
	public static async IAsyncEnumerable<T> DistinctAsync<T>(this IAsyncEnumerable<T> values)
	{
		var uniqueValues = new HashSet<T>();
		await foreach (var value in values)
		{
			if (uniqueValues.Add(value))
				yield return value;
		}
	}

	/// <summary>
	/// Projects each element of an asynchronous sequence into a new form.
	/// </summary>
	/// <param name="values">An asynchronous sequence of values to project.</param>
	/// <param name="selector">A transform function to apply to each element.</param>
	/// <typeparam name="T">The type of elements in the source sequence.</typeparam>
	/// <typeparam name="TR">The type of elements in the resulting sequence.</typeparam>
	/// <returns>An asynchronous sequence whose elements are the result of invoking the transform function on each element of the source.</returns>
	public static async IAsyncEnumerable<TR> SelectAsync<T, TR>(this IAsyncEnumerable<T> values, Func<T, TR> selector)
	{
		await foreach (var value in values)
		{
			yield return selector(value);
		}
	}

	/// <summary>
	/// Projects each element of an asynchronous sequence to an IEnumerable and flattens the resulting sequences into one sequence.
	/// </summary>
	/// <param name="values">An asynchronous sequence of values to project.</param>
	/// <param name="selector">A transform function to apply to each element.</param>
	/// <typeparam name="T">The type of elements in the source sequence.</typeparam>
	/// <typeparam name="TR">The type of elements in the resulting sequence.</typeparam>
	/// <returns>An asynchronous sequence whose elements are the result of invoking the transform function on each element of the source and then flattening the results.</returns>
	public static async IAsyncEnumerable<TR> SelectManyAsync<T, TR>(this IAsyncEnumerable<T> values, Func<T, IEnumerable<TR>> selector)
	{
		await foreach (var valueSet in values)
		foreach (var value in selector(valueSet))
		{
			yield return value;
		}
	}

	/// <summary>
	/// Projects each element of an asynchronous sequence to an IAsyncEnumerable and flattens the resulting asynchronous sequences into one sequence.
	/// </summary>
	/// <param name="values">An asynchronous sequence of values to project.</param>
	/// <param name="selector">A transform function to apply to each element.</param>
	/// <typeparam name="T">The type of elements in the source sequence.</typeparam>
	/// <typeparam name="TR">The type of elements in the resulting sequence.</typeparam>
	/// <returns>An asynchronous sequence whose elements are the result of invoking the transform function on each element of the source and then flattening the asynchronous results.</returns>
	public static async IAsyncEnumerable<TR> SelectManyAsync<T, TR>(this IAsyncEnumerable<T> values, Func<T, IAsyncEnumerable<TR>> selector)
	{
		await foreach (var valueSet in values)
		await foreach (var value in selector(valueSet))
		{
			yield return value;
		}
	}

	/// <summary>
	/// Filters an asynchronous sequence of values based on a predicate.
	/// </summary>
	/// <param name="values">An asynchronous sequence to filter.</param>
	/// <param name="condition">A function to test each element for a condition.</param>
	/// <typeparam name="T">The type of elements in the source sequence.</typeparam>
	/// <returns>An asynchronous sequence that contains elements from the input sequence that satisfy the condition.</returns>
	public static async IAsyncEnumerable<T> WhereAsync<T>(this IAsyncEnumerable<T> values, Func<T, bool> condition)
	{
		await foreach (var value in values)
		{
			if (condition(value))
				yield return value;
		}
	}

	/// <summary>
	/// Returns the first element of an asynchronous sequence, or a default value if no such element is found.
	/// </summary>
	/// <param name="values">An asynchronous sequence to return the first element of.</param>
	/// <typeparam name="T">The type of elements in the source sequence.</typeparam>
	/// <returns>A task that represents the asynchronous operation. The task result contains the first element in the sequence,
	/// or the default value for the type if the sequence contains no elements.</returns>
	public static async Task<T?> FirstOrDefaultAsync<T>(this IAsyncEnumerable<T> values)
	{
		await foreach (var value in values)
		{
			return value;
		}

		return default;
	}

	/// <summary>
	/// Creates a List from an IAsyncEnumerable by enumerating it asynchronously.
	/// </summary>
	/// <param name="values">An asynchronous sequence to create a list from.</param>
	/// <typeparam name="T">The type of elements in the source sequence.</typeparam>
	/// <returns>A task that represents the asynchronous operation. The task result is a list that contains elements from the input sequence.</returns>

	public static async Task<List<T>> ToListAsync<T>(this IAsyncEnumerable<T> values)
	{
		var result = new List<T>();

		await foreach (var value in values)
		{
			result.Add(value);
		}

		return result;
	}

	/// <summary>
	/// Converts an IEnumerable to an IAsyncEnumerable.
	/// </summary>
	/// <param name="sequence">A sequence to convert to an asynchronous sequence.</param>
	/// <typeparam name="T">The type of elements in the source sequence.</typeparam>
	/// <returns>An IAsyncEnumerable that contains elements from the input sequence.</returns>
	public static IAsyncEnumerable<T> AsAsync<T>(this IEnumerable<T> sequence) => new AsyncEnumerable<T>(sequence);

	private sealed class AsyncEnumerable<T> : IAsyncEnumerable<T>
	{
		public AsyncEnumerable(IEnumerable<T> sequence)
		{
			_sequence = sequence;
		}

		private readonly IEnumerable<T> _sequence;

		public IAsyncEnumerator<T> GetAsyncEnumerator(CancellationToken cancellationToken = default)
			=> new AsyncEnumerator<T>(_sequence.GetEnumerator(), cancellationToken);
	}

	/// <summary>
	/// Provides an implementation of IAsyncEnumerator for enumerating over a sequence asynchronously.
	/// </summary>
	/// <typeparam name="T">The type of elements in the collection.</typeparam>
	private class AsyncEnumerator<T> : IAsyncEnumerator<T>, IDisposable
	{
		/// <summary>
		/// Initializes a new instance of the AsyncEnumerator class.
		/// </summary>
		/// <param name="enumerator">The enumerator of the underlying collection.</param>
		/// <param name="cancellationToken">The token to monitor for cancellation requests.</param>
		public AsyncEnumerator(IEnumerator<T> enumerator, CancellationToken cancellationToken)
		{
			_enumerator = enumerator;
			_cancellationToken = cancellationToken;
		}

		private readonly IEnumerator<T> _enumerator;
		private readonly CancellationToken _cancellationToken;

		/// <summary>
		/// Gets the element in the collection at the current position of the enumerator.
		/// </summary>
		public T Current => _enumerator.Current;

		/// <summary>
		/// Advances the enumerator asynchronously to the next element of the collection.
		/// </summary>
		/// <returns>A ValueTask that will complete with a result of true if the enumerator was successfully advanced
		/// to the next element, or false if the enumerator has passed the end of the collection.</returns>
		public ValueTask<bool> MoveNextAsync()
			=> ValueTask.FromResult(!_cancellationToken.IsCancellationRequested && _enumerator.MoveNext());

		/// <summary>
		/// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
		/// </summary>
		public void Dispose()
			=> _enumerator.Dispose();

		/// <summary>
		/// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources asynchronously.
		/// </summary>
		public ValueTask DisposeAsync()
		{
			Dispose();
			return ValueTask.CompletedTask;
		}
	}
}
