// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.RichAuthorizationRequests;

/// <summary>
/// Asks the per-type validators whether a grant's <c>authorization_details</c> are still acceptable,
/// without letting them change it.
/// </summary>
/// <remarks>
/// The comparison the out-of-band flows can make on their own is by type, because RFC 9396 §6.1 defines no
/// standardized way to compare two arbitrary entries and says the definition of the type owns that
/// decision. A host that raises an amount inside an entry of a type the request did ask for therefore
/// passes every type check there is. Only the validator for that type can refuse it.
///
/// Apply while FORMING a grant, check while SPENDING one. At the authorization endpoint the validators run
/// as part of building the grant, so what they return is the decision and the caller emits it. Here the
/// grant already exists and the end user has already approved it, out of band and possibly days ago, so a
/// validator rewriting it would change what was approved at a point where nobody is watching. It is asked
/// the same question and its answer is read as yes or no.
/// </remarks>
internal static class GrantedRevalidation
{
    /// <summary>
    /// The error to refuse a grant with, or <c>null</c> when the per-type validators accept it.
    /// </summary>
    /// <param name="policy">The per-type validator dispatch.</param>
    /// <param name="grant">The grant about to be spent.</param>
    /// <param name="client">The client the grant is being issued to.</param>
    /// <param name="cancellationToken">Cancellation token forwarded to the validators.</param>
    public static async Task<OidcError?> RefuseAsync(
        this IAuthorizationDetailsPolicy policy,
        AuthorizedGrant grant,
        ClientInfo client,
        CancellationToken cancellationToken)
    {
        if (grant.Context.AuthorizationDetails is not { Count: > 0 } granted)
            return null;

        // A COPY, because a normalising validator says what it wants by editing the entry it was handed,
        // which every narrowing fixture in this repository does. Passing the live array would let the
        // question rewrite its own subject: the grant would leave here altered, silently, by a call whose
        // whole purpose is to decide rather than to change.
        var probe = (JsonArray)granted.DeepClone();

        var result = await policy.ApplyGrantedAsync(probe, client, cancellationToken);
        if (!result.TryGetFailure(out var error))
            return null;

        // The validator's own description, because it names the entry and the reason; access_denied rather
        // than the validator's code, since by this point the end user approved something the deployment
        // will not issue, and that is a denial rather than a malformed request.
        return new OidcError(ErrorCodes.AccessDenied, error.ErrorDescription);
    }
}
