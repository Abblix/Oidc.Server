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

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Abblix.Utils;

/// <summary>
/// The class provides extension methods for enhancing the functionality and ease of use of strings.
/// </summary>
public static class StringExtensions
{
    /// <summary>
    /// Inserts a specified value into the source string after a specified fragment.
    /// </summary>
    /// <param name="source">The source string where the value will be inserted.</param>
    /// <param name="fragment">The fragment after which the value will be inserted.</param>
    /// <param name="value">The value to insert into the source string.</param>
    /// <returns>A new string with the value inserted.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the fragment is not found in the source string.</exception>
    public static string InsertAfter(this string source, string fragment, string value)
    {
        var i = source.IndexOf(fragment, StringComparison.Ordinal);
        if (i < 0) throw new InvalidOperationException($"Can't find {fragment}");

        return source.Insert(i + fragment.Length, value);
    }

    /// <summary>
    /// Determines whether the specified string is neither null nor empty.
    /// </summary>
    /// <param name="value">The string to test.</param>
    /// <returns>true if the value parameter is not null or an empty string (""); otherwise, false.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [DebuggerStepThrough]
    public static bool HasValue([NotNullWhen(true)] this string? value)
        => !string.IsNullOrEmpty(value);

    /// <summary>
    /// Trims the specified suffix from the end of the string, if it exists.
    /// </summary>
    /// <param name="source">The source string to trim.</param>
    /// <param name="suffix">The suffix to remove if it exists at the end of the source string.</param>
    /// <returns>The string without the specified suffix.</returns>
    public static string TrimSuffixIfExists(this string source, string suffix)
        => !string.IsNullOrEmpty(suffix) && source.EndsWith(suffix) ? source[..^suffix.Length] : source;

    /// <summary>
    /// Ensures that a string is neither null nor empty, throwing an exception if it is.
    /// </summary>
    /// <param name="value">The string to validate.</param>
    /// <param name="valueName">The name of the string variable, used in the exception message.</param>
    /// <returns>The original string if it is neither null nor empty.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the string is null or empty.</exception>
    [DebuggerStepThrough]
    public static string NotNullOrEmpty([NotNull] this string? value, string valueName)
        => !string.IsNullOrEmpty(value) ? value : throw new InvalidOperationException($"{valueName} is expected to be not null or empty");
}
