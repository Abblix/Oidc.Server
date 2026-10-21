// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Narrows the authorization details an access token carries to the resource servers it is addressed to.
/// </summary>
internal static class AuthorizationDetailsAudience
{
    /// <summary>
    /// Drops the <c>authorization_details</c> entries this token's audience has no business reading, when
    /// the deployment has said its <c>locations</c> and its audiences are drawn from the same namespace.
    /// </summary>
    /// <param name="payload">The access token payload, with its audience already settled.</param>
    /// <remarks>
    /// Off unless <see cref="OidcOptions.FilterAuthorizationDetailsByLocation"/> says otherwise, because
    /// nothing here can check that the two members are comparable. RFC 9396 section 2.2 says <c>locations</c>
    /// "typically" holds URIs identifying resource servers, and section 9.1's own example pairs a client-style
    /// <c>aud</c> with a resource URI in <c>locations</c>, so a deployment where they do agree has decided
    /// that, and one where they do not would lose every located entry. section 7 leaves what the token carries to
    /// this server where the client did not ask, and section 13 asks for need-to-know as local policy determines.
    ///
    /// Applied to the ACCESS token only, and here rather than in
    /// <see cref="AuthorizationContextExtensions.ApplyTo"/>, which a refresh token goes through as well. A
    /// refresh token is read by this server rather than by a resource server, and it is what a later refresh
    /// for a DIFFERENT resource is rebuilt from, so narrowing it would protect nobody and would permanently
    /// lose the entries that refresh needs.
    ///
    /// An entry with no <c>locations</c> MEMBER survives. section 2.2 makes it optional, and reading its absence
    /// as "nowhere" would empty the claim for every deployment that does not use it. An entry whose
    /// <c>locations</c> is PRESENT is dropped when none of the strings that member yields names an
    /// audience - so an empty array and a null are dropped, absence and emptiness being different
    /// statements of which only the first is silence.
    ///
    /// The test is a match rather than a check of shape, and that has a consequence worth naming: the
    /// reader accepts a bare string as well as an array and SKIPS elements that are not strings, so
    /// <c>["https://orders.example.com", 7]</c> matches on its first element and the entry is kept. A
    /// partly malformed member can therefore keep an entry alive, which is the opposite direction from
    /// everything else here. Refusing it instead belongs with the five sibling call sites that refuse an
    /// unreadable entry, not in a filter. The member is
    /// REMOVED when nothing survives rather than written as an empty array or a null: section 14.2 registers the
    /// claim as a JSON array, so a null is a document no resource server owes us a reading of, and an empty
    /// array would say the end user granted nothing.
    ///
    /// Comparison is ordinal on the text, per section 12: "No additional transformation or normalization is to be
    /// done in evaluating equivalence of string values."
    /// </remarks>
    internal static void NarrowAuthorizationDetailsToAudience(this JsonWebTokenPayload payload)
    {
        if (payload.Json[IanaClaimTypes.AuthorizationDetails] is not JsonArray details)
            return;

        var addressed = payload.Audiences.ToHashSet(StringComparer.Ordinal);

        var kept = details
            .ToTypedArray()?
            .Where(detail => detail.Locations is not { } locations ||
                             locations.Any(location => addressed.Contains(location)))
            .ToRawJsonArray();

        payload.Json.SetProperty(
            IanaClaimTypes.AuthorizationDetails,
            kept is { Count: > 0 } ? kept : null);
    }
}
