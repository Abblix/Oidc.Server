// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.UserInteraction;

/// <summary>
/// Tells the authorization endpoint whether the end user must complete a step of the host's own before anything is
/// issued to them: accepting a new version of the terms, a mandatory password change, completing a profile.
/// </summary>
/// <remarks>
/// The endpoint asks once a single session answers the request, and before it reads the consents, so a step is
/// completed before the end user grants anything. A required step sends the end user to
/// <c>OidcOptions.InteractionUri</c> with <see cref="InteractionRequired"/>, and answers the client with
/// <c>interaction_required</c> when the request carries <c>prompt=none</c> (OpenID Connect Core 1.0, section 3.1.2.6).
/// <para>
/// The host records that the step is completed, and the request coming back from the interaction page is answered
/// that no step is required. Completing a step by signing the end user in again would move the authentication time
/// without anyone having authenticated, and a request's <c>max_age</c> would then accept a session it should send to
/// the login page.
/// </para>
/// <para>
/// Neither the device authorization grant nor CIBA asks this: on both the host already runs the end user's approval,
/// on its verification page or on the authentication device, and puts any step of its own there.
/// </para>
/// <para>
/// Under multi-tenancy the server asks the same implementation for every tenant; a host keeping its steps per tenant
/// reads the tenant of the request from <c>ITenantAccessor</c>.
/// </para>
/// </remarks>
public interface IUserInteractionRequirement
{
    /// <summary>
    /// Whether the end user of <paramref name="authSession"/> must complete a step before
    /// <paramref name="request"/> is authorized.
    /// </summary>
    /// <param name="request">The validated authorization request.</param>
    /// <param name="authSession">The session selected to answer the request.</param>
    Task<bool> IsRequiredAsync(ValidAuthorizationRequest request, AuthSession authSession);
}
