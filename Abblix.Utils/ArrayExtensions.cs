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
/// Provides extension methods for arrays.
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
}
