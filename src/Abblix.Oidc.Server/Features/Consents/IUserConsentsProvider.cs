// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Consents;

/// <summary>
/// Defines an interface for a service that provides user consents. This service is responsible for retrieving
/// and managing user consent decisions related to authorization requests. It ensures that the application adheres
/// to user preferences and legal requirements concerning data access and processing.
/// </summary>
/// <remarks>
/// Under multi-tenancy the consents stay the host's: the server does not partition this provider by tenant, so every
/// tenant asks the same one, and a consent the host records without the tenant counts at every tenant serving a
/// client under the same id. A host keeps each consent under the tenant of the request, read from
/// <c>ITenantAccessor</c>, and answers only with the consents given at that tenant.
/// <para>
/// What the provider grants must stay within what the request asked for, and the two halves of that are kept in
/// different places. The server refuses on its own a granted scope, resource or <c>authorization_details</c>
/// type the request did not carry. Whether a granted entry stays within the requested ones of its type - an
/// amount no higher, the same account - only the type's <c>IAuthorizationDetailValidator</c> can tell, and the
/// server asks it with the requested entries in hand; a type registered without that comparison applies only
/// the rules it applies to a request, so a provider that copies a consent form's answer back must compare it
/// itself or register a validator that does.
/// </para>
/// </remarks>
public interface IUserConsentsProvider
{
    /// <summary>
    /// Asynchronously retrieves the user consents for a given authorization request and authentication session.
    /// This method is essential for determining which scopes and resources the user has consented to, enabling
    /// the application to respect user permissions and comply with data protection regulations.
    /// </summary>
    /// <param name="request">The validated authorization request containing the scopes and resources for which
    /// consent may be required.</param>
    /// <param name="authSession">The current authentication session that provides context about the authenticated user,
    /// potentially influencing consent retrieval based on the user's settings or previous consent decisions.</param>
    /// <returns>A task that resolves to an instance of <see cref="UserConsents"/>, containing detailed information
    /// about the consents granted or denied by the user.</returns>
    Task<UserConsents> GetUserConsentsAsync(ValidAuthorizationRequest request, AuthSession authSession);
}
