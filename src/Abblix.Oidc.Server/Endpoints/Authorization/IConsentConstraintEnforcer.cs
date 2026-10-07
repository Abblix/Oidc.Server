// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Defense-in-depth backstop that asserts the anti-escalation invariant on the consent decision:
/// the set granted by <see cref="IUserConsentsProvider"/> MUST be a subset of what the
/// authorization request carried. This mirrors the strictly narrowing-only
/// <see cref="Abblix.Oidc.Server.Endpoints.Token.Interfaces.ITokenAuthorizationContextEvaluator"/> at
/// the token endpoint (RFC 8707 section 2.2), giving the authorize-time consent path the same guarantee.
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
/// <para>
/// One refusal is a protocol answer instead: a per-type validator holding a granted entry to the
/// requested ones and finding it wider - a higher amount, another account. With both entries in hand the
/// likely cause is an end user who edited the consent form rather than a defect in the host's code, so
/// it is returned as an error and the client is told access_denied.
/// </para>
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
    /// <returns>The granted <c>authorization_details</c> as re-validated, an empty array when the
    /// consent decision carried none, or an <c>access_denied</c> error when a per-type validator refused
    /// a granted entry. A re-validation that removes every entry throws instead, so an empty array never
    /// means "the validators emptied it". When the consent decision carries no authorization_details list
    /// at all, the requested entries are issued and this answer is not used for them.</returns>
    /// <remarks>
    /// What this bounds is TYPES and shapes, and deliberately not cardinality: a per-type validator
    /// answering with several entries of a type the user did grant is accepted, because RFC 9396 offers
    /// no comparator that would say whether three entries of a type narrow one. A deployment that needs
    /// that bound sets it inside the per-type validator, which is the only place that knows what a
    /// second entry of its own type means.
    /// </remarks>
    /// <remarks>
    /// RFC 9396 section 6.1 defines no universal comparator for "is this entry a narrowing of that one", so the
    /// per-type validator owns that decision - and a normalising validator expresses it by RETURNING
    /// a modified entry rather than by failing. The value that comes back is therefore the decision
    /// itself, and the caller emits it; emitting what went in instead would put content in the token
    /// that no validator approved.
    /// </remarks>
    /// <exception cref="InvalidOperationException">Thrown when the granted set contains a scope, resource
    /// or resource scope the request did not carry, or an <c>authorization_details</c> type it did not
    /// carry; and equally when the array leaving the per-type re-validation does, since that is the one the
    /// grant is built from. Also thrown when an entry cannot be read as a JSON object, when one carries no
    /// <c>type</c>, and when the re-validation answers with an empty set, which says every entry was removed
    /// and leaves nothing to issue a grant for. Content within a requested type that is wider than the
    /// request is answered with access_denied instead.</exception>
    Task<Result<JsonArray, OidcError>> EnforceAsync(
        ValidAuthorizationRequest request,
        ConsentDefinition granted,
        CancellationToken cancellationToken);
}
