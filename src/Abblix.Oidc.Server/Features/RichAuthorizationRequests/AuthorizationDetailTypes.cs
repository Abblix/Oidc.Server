// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.RichAuthorizationRequests;

/// <summary>
/// The <c>authorization_details</c> types an array names.
/// </summary>
/// <remarks>
/// One computation, because four places compare a grant against what was requested and every one of them
/// needs the same answer to "which types does this array name". A predicate deciding a branch and a branch
/// re-deriving the same fact by a slightly different test disagree on exactly the inputs nobody wrote a
/// test for, and four verbatim copies are four chances for one of them to drift.
/// </remarks>
internal static class AuthorizationDetailTypes
{
    /// <summary>
    /// The distinct types the entries name, comparing as text.
    /// </summary>
    /// <param name="details">The entries, or <c>null</c>.</param>
    /// <returns>The named types; empty when there are none to name.</returns>
    /// <remarks>
    /// Unreadable and typeless entries are DROPPED rather than refused, which narrows the set and
    /// therefore admits less wherever it is used as a baseline. The grant side of each comparison has to
    /// refuse instead, because there the same silence would admit more, and that refusal stays with the
    /// caller that owns it.
    ///
    /// Whether a null array means "asked for nothing" or "predates the field" is likewise the caller's
    /// to decide, and the two flows decide it differently on purpose. This answers the same for both,
    /// which is why it can be shared: a caller that treats null as unknown returns before asking.
    ///
    /// Compared as text, per RFC 9396 §12: "All string comparisons in an authorization_details parameter
    /// are to be done as defined by [RFC8259]. No additional transformation or normalization is to be
    /// done in evaluating equivalence of string values."
    /// </remarks>
    public static HashSet<string> NamedBy(JsonArray? details)
        => (details?.ToTypedArray() ?? [])
            .Select(detail => detail.Type)
            .OfType<string>()
            .ToHashSet(StringComparer.Ordinal);
}
