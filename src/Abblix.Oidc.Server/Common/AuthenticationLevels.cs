// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Whether an authentication at a given level answers what a request asked of it.
/// </summary>
/// <remarks>
/// One rule for every place a session's level is judged - choosing a session at the authorization endpoint,
/// issuing an ID token, completing and redeeming a decoupled authentication - so the answer for the same
/// session cannot differ between them.
/// </remarks>
internal static class AuthenticationLevels
{
    /// <summary>
    /// Whether an authentication at <paramref name="level"/> is one of <paramref name="accepted"/>, an empty
    /// set accepting any.
    /// </summary>
    /// <remarks>
    /// A session recording no level, or an empty one, meets no named level: it says nothing about how the end
    /// user authenticated.
    /// </remarks>
    public static bool Accept(IReadOnlyCollection<string> accepted, string? level)
        => accepted.Count == 0 || level.HasValue() && accepted.Contains(level, StringComparer.Ordinal);

    /// <summary>
    /// Whether an authentication at <paramref name="level"/> meets the levels a decoupled request required:
    /// the ones <paramref name="recorded"/> when it arrived, or, for a request stored before they were
    /// recorded, the ones its grant's <paramref name="claims"/> require.
    /// </summary>
    public static bool Accept(string[]? recorded, RequestedClaims? claims, string? level)
        => recorded is { } levels
            ? Accept(levels, level)
            : claims.AcceptsAuthenticationLevel(level);
}
