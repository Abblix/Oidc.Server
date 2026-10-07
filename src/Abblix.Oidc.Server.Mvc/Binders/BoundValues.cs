// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// What the MVC model binding hands over, put into the shape the core models hold.
/// </summary>
internal static class BoundValues
{
    /// <summary>
    /// A repeated parameter without the entries that bound to nothing, or null when none is left.
    /// </summary>
    /// <remarks>
    /// ASP.NET Core binds an entry that is empty or whitespace alone to null, and the Minimal API host drops the
    /// same entries, so both hosts read the parameter alike: <c>resource=%20</c> is no resource.
    /// </remarks>
    public static T[]? WithoutEmptyEntries<T>(T?[]? values) where T : class
        => values?.OfType<T>().ToArray() is { Length: > 0 } entries ? entries : null;
}
