// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Defines the details of user consents required for specific scopes and resources.
/// This record is used to manage and validate user consent for accessing specific scopes, resources, and
/// RFC 9396 Rich Authorization Requests entries, ensuring that consent is explicitly granted according to
/// the requirements of the application and compliance standards.
/// </summary>
/// <param name="Scopes">An array of <see cref="ScopeDefinition"/> that represents the scopes for which user consent
/// is needed.</param>
/// <param name="Resources">An array of <see cref="ResourceDefinition"/> that represents the resources for which
/// user consent is needed.</param>
public record ConsentDefinition(ScopeDefinition[] Scopes, ResourceDefinition[] Resources)
{
    /// <summary>
    /// RFC 9396 <c>authorization_details</c> entries for which user consent is needed (in
    /// <see cref="UserConsents.Pending"/>) or has been granted (in <see cref="UserConsents.Granted"/>).
    /// <c>null</c> when the request did not include <c>authorization_details</c>.
    /// </summary>
    /// <remarks>
    /// The two sets are independent, so a decision is made per entry: an entry the user has approved goes to
    /// <see cref="UserConsents.Granted"/> while another from the same request is still waiting in
    /// <see cref="UserConsents.Pending"/>. Anything left pending sends the request back for consent, and the
    /// screen is shown what is pending rather than what has already been granted.
    /// <para>
    /// A granted entry is whatever the provider returns, which RFC 9396 section 7.1 permits to differ from
    /// what was requested, in either direction: dropping an entry keeps it out of the issued token, editing
    /// one inside (an amount narrowed by a slider) is carried through as edited, and the section's own example
    /// is the opposite case, the server filling in the accounts a user picked. What is refused is a granted
    /// entry of a <c>type</c> the request did not carry; within an entry, the per-type validator decides.
    /// </para>
    /// <para>
    /// Only the authorization endpoint consults this. A backchannel authentication request has no consent seam
    /// at all, and the device flow surfaces the requested entries for the host to carry onto the grant itself.
    /// </para>
    /// <para>
    /// The storage is raw so that member order, type-specific payload and members this server does not model
    /// survive the round trip untouched. For rendering a consent screen, read the same entries as
    /// <see cref="Abblix.Jwt.AuthorizationDetail"/> through <c>ToTypedArray()</c>: the typed view wraps these
    /// nodes rather than copying them, so it names the RFC 9396 section 2.2 common members without costing the
    /// rest.
    /// </para>
    /// </remarks>
    public JsonArray? AuthorizationDetails { get; init; }
}
