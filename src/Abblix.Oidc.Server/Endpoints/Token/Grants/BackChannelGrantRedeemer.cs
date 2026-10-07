// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using StoredRequest = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationRequest;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Redeems an authenticated backchannel authentication request, refusing it when the grant is not one the
/// request asked for: another end user, a weaker authentication, or wider authorization_details.
/// </summary>
/// <remarks>
/// Each of those is a specification the grant must satisfy (Specification), and the grant is judged against
/// them twice - see <see cref="RedeemAsync"/> for why.
/// </remarks>
/// <param name="loggerFactory">Creates the logger that records a refusal the client is deliberately told nothing
/// specific about. It writes under the grant handler's category, since the refusal is the token endpoint's answer
/// to a CIBA grant.</param>
/// <param name="subjectTypeConverter">Seals the authenticated session's subject the way the requesting
/// client sees it, so it can be compared against the end user the original request named.</param>
/// <param name="authorizationDetailsPolicy">Asks the per-type validators whether the grant's
/// authorization_details are still acceptable, which is the only comparison that can see inside an
/// entry.</param>
internal sealed partial class BackChannelGrantRedeemer(
    ILoggerFactory loggerFactory,
    ISubjectTypeConverter subjectTypeConverter,
    IAuthorizationDetailsPolicy authorizationDetailsPolicy)
{
    private readonly ILogger _logger = loggerFactory.CreateLogger<BackChannelAuthenticationGrantHandler>();

    /// <summary>
    /// Redeems an authenticated request, refusing it when the end user who authenticated is not one it
    /// named.
    /// </summary>
    /// <remarks>
    /// OpenID Connect Core 1.0 Section 3.1.2.2: the server "MUST NOT reply with an ID Token or Access Token
    /// for a different user, even if they have an active session with the Authorization Server". In a
    /// decoupled flow the end user authenticates out of band, so what the request named is compared against
    /// whoever the host reported by the time a grant is asked for.
    /// <para>
    /// Judged twice, on two different objects, because one comparison cannot do both jobs. Before the
    /// request is consumed, so an ordinary mismatch spends nothing - redeeming removes the stored entry.
    /// And again on the grant the processor returned, because the processor consumes the stored request
    /// itself, and between the earlier read and that removal a host - writing to that same storage through
    /// the public seam - can replace what is stored. Judging only the earlier copy would approve one grant
    /// and hand over another.
    /// </para>
    /// </remarks>
    public async Task<Result<AuthorizedGrant, OidcError>> RedeemAsync(
        string authenticationRequestId,
        StoredRequest request,
        ClientInfo clientInfo,
        IBackChannelGrantProcessor processor)
    {
        var yardstick = BackChannelGrantYardstick.Of(request);

        if (RefuseBeforeRedemption(yardstick, clientInfo) is { } early)
            return early;

        var result = await processor.ProcessAuthenticatedRequestAsync(authenticationRequestId, request);
        if (result.TryGetFailure(out var error))
            return error;

        var grant = result.GetSuccess();

        if (RefuseRedeemed(yardstick, grant, clientInfo) is { } late)
            return late;

        // And what the type comparison structurally cannot see: an entry of a type the request DID ask
        // for, carrying content it did not. RFC 9396 section 6.1 leaves that to the type's own validator, so this
        // asks it - on a copy, because the question must not rewrite its own subject. Without the caller's
        // cancellation token, because the request is already taken: giving up here would spend it and issue
        // nothing, where finishing issues tokens a departed client simply never reads.
        if (await authorizationDetailsPolicy.RefuseAsync(
                grant, request.RequestedAuthorizationDetails, clientInfo, CancellationToken.None)
            is not { } refusal)
            return grant;

        // The reason goes to the log and a fixed string to the client: a granted-phase rejection names
        // a host-side defect, and its text is written for whoever has to fix it.
        LogGrantedAuthorizationDetailsRefused(clientInfo.ClientId, refusal.Reason);
        return refusal.Error;
    }

    /// <summary>
    /// Judges the grant as stored, before the request is consumed, so an ordinary mismatch costs the client
    /// nothing it could have used: redeeming removes the entry, and a request answerable only for the wrong
    /// end user is worth keeping just long enough to say so again if the client polls twice.
    /// </summary>
    private OidcError? RefuseBeforeRedemption(BackChannelGrantYardstick yardstick, ClientInfo clientInfo)
    {
        var storedGrant = yardstick.Request.AuthorizedGrant;

        if (!NamesTheRequestedEndUser(yardstick.NamedEndUsers, storedGrant, clientInfo))
            return NotTheRequestedEndUser();

        if (WidensTheRequest(yardstick.Request, storedGrant))
            return NotWhatTheRequestAskedFor();

        // The completion path refuses an authentication at a level the request's essential acr does not
        // accept, but a host writing Authenticated straight into the storage it owns never passes through
        // it, and the client then simply polls. OpenID Connect Core 1.0 Section 5.5.1.1 makes that outcome a
        // failed authentication attempt either way.
        if (!AcceptsRecordedLevel(yardstick, storedGrant))
            return NotTheRequiredAuthenticationLevel();

        return null;
    }

    /// <summary>
    /// Judges again, on what was actually consumed.
    /// </summary>
    /// <remarks>
    /// The processor removes the stored entry and returns the grant it found there, so between the check
    /// before redemption and that removal a host - writing to that same storage through the public seam - can
    /// replace what is stored, which is the ordinary shape of a retried or corrected completion rather than an
    /// attack. Approving one grant and handing over another is the whole failure this comparison exists to
    /// prevent.
    /// </remarks>
    private OidcError? RefuseRedeemed(BackChannelGrantYardstick yardstick, AuthorizedGrant grant, ClientInfo clientInfo)
    {
        if (!NamesTheRequestedEndUser(yardstick.NamedEndUsers, grant, clientInfo))
            return NotTheRequestedEndUser();

        if (!AcceptsRecordedLevel(yardstick, grant))
            return NotTheRequiredAuthenticationLevel();

        // And the same for what the grant authorises. The completion path judges this too, but a host can
        // complete with a narrowed grant and then store a wider one before the client polls - the same
        // window the subject comparison above exists for, and the same answer.
        if (WidensTheRequest(yardstick.Request, grant))
            return NotWhatTheRequestAskedFor();

        return null;
    }

    /// <summary>
    /// Whether this grant belongs to the end user the request named, or the request named nobody.
    /// </summary>
    /// <remarks>
    /// The name is taken from the request as it was read, since it is written once when the request is
    /// created and a host has no reason to touch it. What a host does replace is the session, which is what
    /// each caller passes in.
    /// </remarks>
    private bool NamesTheRequestedEndUser(
        string[]? requestedSubjects, AuthorizedGrant grant, ClientInfo clientInfo)
        => requestedSubjects is not { } accepted ||
           subjectTypeConverter.Names(grant.AuthSession, accepted, clientInfo);

    private static bool AcceptsRecordedLevel(BackChannelGrantYardstick yardstick, AuthorizedGrant grant)
        => AuthenticationLevels.Accept(
            yardstick.RecordedLevels, yardstick.RequiredClaims, grant.AuthSession.AuthContextClassRef);

    /// <summary>
    /// Whether the grant carries an <c>authorization_details</c> type the request never asked for.
    /// </summary>
    /// <remarks>
    /// Types only, for the reason the completion path gives: RFC 9396 section 6.1 defines no universal
    /// comparator for
    /// intra-entry narrowing. A null baseline means the request predates the field rather than asked for
    /// nothing, and is left alone, since refusing it would deny an authentication the end user approved
    /// before the upgrade.
    /// </remarks>
    private static bool WidensTheRequest(StoredRequest request, AuthorizedGrant grant)
    {
        if (grant.Context.AuthorizationDetails is not { Count: > 0 } granted ||
            request.RequestedAuthorizationDetails is not { } requested)
            return false;

        if (granted.ToTypedArray() is not { } typed || typed.Length != granted.Count)
            return true;

        var requestedTypes = AuthorizationDetailTypes.NamedBy(requested);

        return !typed.All(detail => detail.Type is { } type && requestedTypes.Contains(type));
    }

    private static OidcError NotTheRequestedEndUser()
        => new(ErrorCodes.AccessDenied, "The authenticated end user is not the one the request named");

    private static OidcError NotTheRequiredAuthenticationLevel()
        => new(ErrorCodes.AccessDenied, "The end user authenticated at a level the request does not accept");

    private static OidcError NotWhatTheRequestAskedFor()
        => new(ErrorCodes.AccessDenied,
            "The grant carries authorization_details the authentication request did not ask for");
}
