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
/// Extension methods for <see cref="Enum"/> values that complement the BCL surface.
/// </summary>
public static class EnumExtensions
{
    /// <summary>
    /// Returns <c>true</c> when at least one flag in <paramref name="mask"/> is set in
    /// <paramref name="value"/>. The OR-counterpart to <see cref="Enum.HasFlag"/>:
    /// <c>HasFlag(mask)</c> requires every bit of <paramref name="mask"/> to be set, while this
    /// method is satisfied by any single bit. Callers should build the mask inline by OR-ing the
    /// individual flags they want to test for, rather than reusing a named composite enum member
    /// whose semantics may match <see cref="Enum.HasFlag"/> (all-of) instead of any-of.
    /// </summary>
    /// <typeparam name="T">A <c>[Flags]</c> enum type.</typeparam>
    /// <param name="value">The flag value to inspect.</param>
    /// <param name="mask">An OR of the flags to test for.</param>
    /// <returns><c>true</c> when any flag in <paramref name="mask"/> is set in
    /// <paramref name="value"/>; otherwise <c>false</c>.</returns>
    public static bool HasAnyFlag<T>(this T value, T mask) where T : struct, Enum
        => (Convert.ToInt64(value) & Convert.ToInt64(mask)) != 0;
}
