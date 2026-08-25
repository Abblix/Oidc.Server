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
/// <param name="Error">The answer for a client that is waiting for one, deliberately saying nothing
/// specific.</param>
/// <param name="Reason">The validator's own words, for the log.</param>
/// <remarks>
/// Two strings because they have two audiences. A granted-phase rejection names a HOST-side defect, so the
/// validator writes for whoever has to fix it and may name a tenant, a ceiling or a configuration key. That
/// is not a sentence a client asking for a token should receive, and no other granted-phase refusal in this
/// library reaches one - the authorization endpoint wraps its own in an exception.
///
/// One caller has no client to answer and uses <c>Reason</c> alone: the CIBA push mode delivers through a
/// notification endpoint this server sends no error payload to, so there is nowhere for <c>Error</c> to go.
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
/// Reached from the token endpoint, where the device flow and the CIBA poll and ping modes redeem, and
/// from
/// <see cref="BackChannelAuthentication.AuthenticationNotifiers.PushModeCompletionHandler"/>, which is
/// where the CIBA PUSH mode spends its grant instead - its tokens are minted at completion and posted to
/// the client, so it never travels through the token endpoint at all.
///
/// Deliberately NOT asked at completion for poll and ping. They meet it at redemption, and asking earlier
/// would pre-empt rather than add: a refusal at completion is a denial, and a denied CIBA request reaches
/// its client as <c>access_denied</c> rather than as the code registered for this condition.
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
        var asStored = (JsonArray)granted.DeepClone();
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
        //
        // Compared STRUCTURALLY rather than as text. Deserialise, validate, return a fresh entry is the
        // natural way to write a validator in C#, and the interface invites it, so a validator that changed
        // nothing but the order its members came out in would be accused of changing the grant - refused,
        // and told so in a log naming a change that does not exist.
        //
        // One residual, accepted knowingly: DeepEquals compares a JSON number by its text on .NET 8 and by
        // its value from .NET 10, so a validator that reads a member as a double and writes it back turns
        // 1.0 into 1 and is refused on the older runtime alone. Fail-closed, and the same deployment on two
        // runtimes will disagree about the same validator, which is worth knowing when one does.
        var revalidated = result.GetSuccess();
        var changed = !JsonNode.DeepEquals(probe, asStored) ||
                      (revalidated is not null && !JsonNode.DeepEquals(revalidated, asStored));

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
    /// RFC 9396 §14.6 registers <c>invalid_authorization_details</c> with the token endpoint among its
    /// usage locations, and points its Reference at §5, which is the requirement being enforced here: the
    /// authorization server MUST refuse authorization details not conforming to the respective type
    /// definition. Applying that requirement again when a stored grant is spent is this library's choice
    /// about WHEN, not something the specification asks for - §6 covers a different case, the
    /// <c>authorization_details</c> token request parameter, and nothing is requested on these flows.
    ///
    /// It is also the only available code that is TRUE on the flows that answer a waiting client - CIBA
    /// Core §11 defines <c>access_denied</c> as "The end-user denied the authorization request", and here
    /// the end user approved while the deployment refused. The push mode answers nobody and discards this
    /// code, which is why keeping poll and ping on the redemption path matters: they are the ones that can
    /// still be told the truth.
    /// </remarks>
    private static GrantRefusal Refusal(string? reason)
        => new(
            new OidcError(
                ErrorCodes.InvalidAuthorizationDetails,
                "The granted authorization_details are not ones this deployment will issue"),
            reason ?? "The per-type validators refused the granted authorization_details.");
}
