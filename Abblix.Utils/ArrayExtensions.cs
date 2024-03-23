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
