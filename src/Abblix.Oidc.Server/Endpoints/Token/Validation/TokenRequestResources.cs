// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// The resources a token request speaks for, read by the step judging the scope it names and by the one building the
/// token, so a scope is judged against the resources the token is issued for.
/// </summary>
internal static class TokenRequestResources
{
    /// <summary>
    /// The resources of <paramref name="granted"/> a request naming <paramref name="named"/> speaks for: the ones it
    /// names, or all of them when it names none (RFC 8707 section 2.2).
    /// </summary>
    /// <remarks>
    /// A named resource outside the grant refuses the request (<see cref="GrantNarrowingValidator"/>), so it is never
    /// spoken for.
    /// </remarks>
    public static Uri[]? SpokenFor(Uri[]? granted, IEnumerable<Uri> named)
    {
        Uri[] requested = [.. named];
        return granted is { Length: > 0 } && requested.Length > 0
            ? [.. granted.Intersect(requested)]
            : granted;
    }
}
