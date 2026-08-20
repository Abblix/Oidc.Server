// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Utils;

/// <summary>
/// Provides extension methods for objects to ensure non-null values.
/// </summary>
public static class ObjectExtensions
{
	/// <summary>
	/// Ensures that the specified nullable reference type is not null.
	/// Throws an InvalidOperationException if it is null.
	/// </summary>
	/// <typeparam name="T">The type of the nullable reference type.</typeparam>
	/// <param name="value">The nullable reference type to check for null.</param>
	/// <param name="valueName">The name of the nullable reference type, which will be used in the exception message if the value is null.</param>
	/// <returns>The original non-null value of type T.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the input value is null.</exception>
	public static T NotNull<T>([NotNull] this T? value, string valueName) where T : class
		=> value ?? throw new InvalidOperationException($"{valueName} is expected to be not null");

	/// <summary>
	/// Ensures that the specified nullable value type is not null.
	/// Throws an InvalidOperationException if it is null.
	/// </summary>
	/// <typeparam name="T">The type of the nullable value type.</typeparam>
	/// <param name="value">The nullable value type to check for null.</param>
	/// <param name="valueName">The name of the nullable value type, which will be used in the exception message if the value is null.</param>
	/// <returns>The original non-null value of type T.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the input value is null.</exception>
	public static T NotNull<T>([NotNull] this T? value, string valueName) where T : struct
		=> value ?? throw new InvalidOperationException($"{valueName} is expected to be not null");

	/// <summary>
	/// Wraps a single value as an <see cref="IAsyncEnumerable{T}"/> that yields exactly
	/// one element. Useful for adapting non-streaming sources to APIs that consume an
	/// async sequence - for example handing a single signing key to a verifier that
	/// expects a candidate-key stream.
	/// </summary>
	/// <typeparam name="T">The type of the value to wrap.</typeparam>
	/// <param name="value">The value to yield.</param>
	/// <returns>An <see cref="IAsyncEnumerable{T}"/> producing <paramref name="value"/>
	/// once and then completing.</returns>
	public static async IAsyncEnumerable<T> ToAsync<T>(this T value)
	{
		yield return value;
		await Task.CompletedTask;
	}
}
