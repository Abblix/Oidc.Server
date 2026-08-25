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
/// Why a grant's <c>authorization_details</c> will not be issued: what the client is told, and what the
/// operator is told.
/// </summary>
/// <param name="Error">The answer that goes on the wire, deliberately saying nothing specific.</param>
/// <param name="Reason">The validator's own words, for the log.</param>
/// <remarks>
/// Two strings because they have two audiences. A granted-phase rejection names a HOST-side defect, so the
/// validator writes for whoever has to fix it and may name a tenant, a ceiling or a configuration key. That
/// is not a sentence a client asking for a token should receive, and no other granted-phase refusal in this
/// library reaches one - the authorization endpoint wraps its own in an exception.
/// </remarks>
internal readonly record struct GrantRefusal(OidcError Error, string Reason);

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
/// validator rewriting it would change what was approved at a point where nobody is watching.
/// </remarks>
internal static class GrantedRevalidation
{
    /// <summary>
    /// Why the grant will not be issued, or <c>null</c> when the per-type validators accept it as stored.
    /// </summary>
    /// <param name="policy">The per-type validator dispatch.</param>
    /// <param name="grant">The grant about to be spent.</param>
    /// <param name="client">The client the grant is being issued to.</param>
    /// <param name="cancellationToken">Cancellation token forwarded to the validators.</param>
    public static async Task<GrantRefusal?> RefuseAsync(
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
        var asStored = granted.ToJsonString();
        var probe = (JsonArray)granted.DeepClone();

        var result = await policy.ApplyGrantedAsync(probe, client, cancellationToken);
        if (result.TryGetFailure(out var error))
            return Refusal(error.ErrorDescription);

        // A validator that CHANGES the grant is refusing it. Discarding the change would be the same hole
        // inverted: a validator expressing its ceiling by capping an amount rather than by saying no
        // answers success, and the deployment would then issue more than its own validator permits - while
        // the authorization endpoint, which consumes the answer, issues the capped value for the same
        // client. Both ways of writing a validator are honoured here, and at this point both mean one
        // thing: what is stored is not what may be issued.
        //
        // Both shapes are compared, because the two ways of answering are equally common: an edit IN PLACE
        // shows on the probe, a rewritten entry shows in what comes back. Null means nothing to change,
        // which is how every other caller reads it.
        var revalidated = result.GetSuccess();
        var changed = probe.ToJsonString() != asStored ||
                      (revalidated is not null && revalidated.ToJsonString() != asStored);

        return changed
            ? Refusal(
                "The per-type validators would change the granted authorization_details, so what is " +
                "stored is not what may be issued.")
            : null;
    }

    /// <summary>
    /// The refusal, with the code RFC 9396 registers for it.
    /// </summary>
    /// <remarks>
    /// RFC 9396 §14.6 registers <c>invalid_authorization_details</c> for the token endpoint, and §6
    /// describes this exact condition: the authorization server checks whether the underlying grant allows
    /// issuing an access token with these details, and refuses with that code otherwise. It is also the
    /// only available code that is TRUE on both flows - CIBA Core §11 defines <c>access_denied</c> as "The
    /// end-user denied the authorization request", and here the end user approved while the deployment
    /// refused.
    /// </remarks>
    private static GrantRefusal Refusal(string? reason)
        => new(
            new OidcError(
                ErrorCodes.InvalidAuthorizationDetails,
                "The granted authorization_details are not ones this deployment will issue"),
            reason ?? "The per-type validators refused the granted authorization_details.");
}
