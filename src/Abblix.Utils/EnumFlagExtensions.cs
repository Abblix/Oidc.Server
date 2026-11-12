// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils;

/// <summary>
/// Extension methods for <c>[Flags]</c> enum values that complement the BCL surface.
/// Named with the <c>Flag</c> qualifier so it does not collide with the very common
/// <c>EnumExtensions</c> class name used by other libraries (e.g. <c>Fido2NetLib.EnumExtensions</c>),
/// which would surface as <c>CS0104</c> in any consumer that imports both namespaces.
/// </summary>
public static class EnumFlagExtensions
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

    /// <summary>
    /// Returns <paramref name="value"/>, or <paramref name="defaultValue"/> when it is zero, the value an enum field
    /// holds when nothing was ever assigned to it.
    /// </summary>
    /// <remarks>
    /// For a <c>[Flags]</c> enum zero is the empty set, which a setting naming what is permitted reads as permitting
    /// nothing, so a value that was never written would otherwise take the strictest meaning rather than the default.
    /// It is meant only for an enum with no member at zero: one that has such a member loses it, read as
    /// <paramref name="defaultValue"/> even when it was written on purpose.
    /// </remarks>
    /// <typeparam name="T">An enum type.</typeparam>
    /// <param name="value">The value as written, possibly never.</param>
    /// <param name="defaultValue">What a zero stands for.</param>
    public static T ByDefault<T>(this T value, T defaultValue) where T : struct, Enum
        => EqualityComparer<T>.Default.Equals(value, default) ? defaultValue : value;
}
