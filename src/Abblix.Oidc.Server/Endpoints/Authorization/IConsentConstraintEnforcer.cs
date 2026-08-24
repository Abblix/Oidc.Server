// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Consents;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Defense-in-depth backstop that asserts the anti-escalation invariant on the consent decision:
/// the set granted by <see cref="IUserConsentsProvider"/> MUST be a subset of what the
/// authorization request carried. This mirrors the strictly narrowing-only
/// <see cref="Abblix.Oidc.Server.Endpoints.Token.Interfaces.ITokenAuthorizationContextEvaluator"/> at
/// the token endpoint (RFC 8707 §2.2), giving the authorize-time consent path the same guarantee.
/// </summary>
/// <remarks>
/// Violating <c>granted ⊆ requested</c> is never a protocol-level condition: the consent decision
/// frequently originates across the browser trust boundary, and a host whose
/// <see cref="IUserConsentsProvider"/> echoes browser-supplied scopes / resources /
/// <c>authorization_details</c> without intersecting against the request would let a user escalate
/// their own grant. The provider returning anything outside the request is a defect in the host's
/// code (or browser tampering its provider failed to defend against), so the enforcer fails loud
/// with an exception rather than masking it as a recoverable OAuth error - it surfaces in the
/// debugger, fails the host's tests, and is logged as a server error in production while no
/// escalated grant is issued.
/// </remarks>
public interface IConsentConstraintEnforcer
{
    /// <summary>
    /// Asserts that the granted consent does not exceed the request, and returns the
    /// <c>authorization_details</c> as the per-type validators left them.
    /// </summary>
    /// <param name="request">The validated authorization request carrying the requested scopes,
    /// resources and <c>authorization_details</c>.</param>
    /// <param name="granted">The consent decision produced by <see cref="IUserConsentsProvider"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The granted <c>authorization_details</c> as re-validated, or <c>null</c> when the
    /// consent decision carried none. A re-validation that returns nothing leaves the granted set
    /// standing, so <c>null</c> never means "the validators emptied it".</returns>
    /// <remarks>
    /// RFC 9396 defines no universal comparator for "is this entry a narrowing of that one", so the
    /// per-type validator owns that decision - and a normalising validator expresses it by RETURNING
    /// a modified entry rather than by failing. The value that comes back is therefore the decision
    /// itself, and the caller emits it; emitting what went in instead would put content in the token
    /// that no validator approved.
    /// </remarks>
    /// <exception cref="InvalidOperationException">Thrown when the granted set contains a scope,
    /// resource, resource scope or <c>authorization_details</c> entry absent from - or broader than -
    /// the request.</exception>
    Task<JsonArray?> EnforceAsync(
        ValidAuthorizationRequest request,
        ConsentDefinition granted,
        CancellationToken cancellationToken);
}
