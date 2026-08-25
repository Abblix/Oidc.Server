// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;

using Abblix.Oidc.Server.Features.RichAuthorizationRequests;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Judges a device grant's <c>authorization_details</c> against what the device asked for.
/// </summary>
/// <remarks>
/// The device flow asks this twice, at approval and again when the device code is redeemed, and the two
/// have to agree on what escaping means. Sharing one computation is what makes them agree: a predicate
/// deciding a branch and a branch re-deriving the same fact by a slightly different test disagree on
/// exactly the inputs nobody wrote a test for.
/// </remarks>
internal static class GrantedAuthorizationDetails
{
    /// <summary>
    /// The <c>authorization_details</c> types the grant carries and the request never asked for, empty
    /// when the grant stays inside what was requested.
    /// </summary>
    /// <param name="request">The stored device authorization request, carrying what the client asked for.
    /// </param>
    /// <param name="grant">The grant a host handed back or stored.</param>
    /// <returns>The escaped type names, or a single entry describing why the grant could not be read.
    /// </returns>
    /// <remarks>
    /// Types only: RFC 9396 §6.1 defines no universal comparator for "is this entry a narrowing of that
    /// one", so what can be judged here is whether an entry of that type was asked for at all. An entry
    /// that cannot be read as a JSON object counts as escaped, because the conversion drops it silently
    /// and "nothing escaped" would then describe what could be read rather than the grant.
    ///
    /// A request carrying no <c>authorization_details</c> is judged strictly rather than skipped: the
    /// member predates this comparison on the stored record, so a null there says the client asked for
    /// nothing rather than that the request was written by a build without the field.
    /// </remarks>
    public static string[] EscapedTypes(DeviceAuthorizationRequest request, AuthorizedGrant grant)
    {
        if (grant.Context.AuthorizationDetails is not { Count: > 0 } granted)
            return [];

        if (granted.ToTypedArray() is not { } typed || typed.Length != granted.Count)
            return ["an entry that is not a JSON object"];

        // Absence is named rather than compared. A typeless entry is refused either way - the request side
        // filters its own types with OfType<string>(), so no request can hold a null to match one with -
        // and what this arm changes is the log: without it the refusal reports an empty string in the list
        // of escaped types, which reads as a defect in the message rather than as the grant's shape.
        if (Array.Exists(typed, detail => detail.Type is null))
            return ["an entry carrying no type"];

        var requestedTypes = AuthorizationDetailTypes.NamedBy(request.AuthorizationDetails);

        return typed
            .Select(detail => detail.Type!)
            .Where(type => !requestedTypes.Contains(type))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }
}
