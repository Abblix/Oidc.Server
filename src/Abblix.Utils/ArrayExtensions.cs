// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils;

/// <summary>
/// Allocation-explicit array helpers: each operation returns a freshly allocated array sized to the result.
/// Prefer these over LINQ when the caller needs a concrete <c>T[]</c> without an extra <c>ToArray()</c> step,
/// or when copying byte buffers via <see cref="Buffer.BlockCopy"/> matters.
/// </summary>
public static class ArrayExtensions
{
    /// <summary>
    /// Appends a value to the end of an array.
    /// </summary>
    /// <param name="array">The array to append to.</param>
    /// <param name="value">The value to append.</param>
    /// <typeparam name="T">The type of the elements in the array.</typeparam>
    /// <returns>A new array with the value appended.</returns>
    /// <remarks>
    /// This method creates a new array with a size larger by one than the original array,
    /// copies all elements from the original array, and adds the specified value at the end.
    /// </remarks>
    public static T[] Append<T>(this T[] array, T value)
    {
        var result = new T[array.Length + 1];
        Array.Copy(array, 0, result, 0, array.Length);
        result[^1] = value;
        return result;
    }

    /// <summary>
    /// Prepends a value to the beginning of an array.
    /// </summary>
    /// <param name="array">The array to prepend to.</param>
    /// <param name="value">The value to prepend.</param>
    /// <typeparam name="T">The type of the elements in the array.</typeparam>
    /// <returns>A new array with the value prepended.</returns>
    /// <remarks>
    /// This method creates a new array with a size larger by one than the original array,
    /// copies all elements from the original array starting from the second position,
    /// and adds the specified value at the beginning.
    /// </remarks>
    public static T[] Prepend<T>(this T[] array, T value)
    {
        var result = new T[array.Length + 1];
        Array.Copy(array, 0, result, 1, array.Length);
        result[0] = value;
        return result;
    }

    /// <summary>
    /// Concatenates two byte arrays into a single array.
    /// </summary>
    /// <param name="first">The first array.</param>
    /// <param name="second">The second array.</param>
    /// <returns>A new array containing all elements from both arrays in order.</returns>
    /// <remarks>
    /// Uses Buffer.BlockCopy for efficient byte-level copying.
    /// </remarks>
    public static byte[] Concat(this byte[] first, byte[] second)
    {
        var result = new byte[first.Length + second.Length];
        Buffer.BlockCopy(first, 0, result, 0, first.Length);
        Buffer.BlockCopy(second, 0, result, first.Length, second.Length);
        return result;
    }

    /// <summary>
    /// Concatenates multiple byte arrays into a single array.
    /// </summary>
    /// <param name="arrays">The arrays to concatenate.</param>
    /// <returns>A new array containing all input arrays concatenated in order.</returns>
    /// <remarks>
    /// Uses Buffer.BlockCopy for efficient byte-level copying.
    /// Returns empty array if no arrays are provided.
    /// </remarks>
    public static byte[] Concat(params byte[][] arrays)
    {
        var totalLength = arrays.Sum(arr => arr.Length);
        var result = new byte[totalLength];
        var offset = 0;

        foreach (var array in arrays)
        {
            Buffer.BlockCopy(array, 0, result, offset, array.Length);
            offset += array.Length;
        }

        return result;
    }
}
