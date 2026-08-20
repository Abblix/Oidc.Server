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
    /// <summary>RFC 9396 <c>authorization_details</c> entries for which user consent is
    /// needed (in <see cref="UserConsents.Pending"/>) or has been granted (in <see cref="UserConsents.Granted"/>).
    /// The provider may return a narrower set than the request carried -- entries removed here never appear in
    /// the issued token; mutations within an entry (e.g. amount narrowed by a UI slider) survive byte-exact
    /// because storage is the raw <see cref="JsonArray"/>. <c>null</c> when the request did not include
    /// <c>authorization_details</c>.</summary>
    public JsonArray? AuthorizationDetails { get; init; }
}
