// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Enforces the end-user confirmation step of OpenID Connect RP-Initiated Logout 1.0 section 2: the OP "MUST ask the
/// End-User this question if an id_token_hint was not provided or if the supplied ID Token does not belong to the
/// current OP session with the RP and/or currently logged in End-User". A request that has to be asked is marked
/// <see cref="EndSessionValidationContext.ConfirmationRequired"/>, and the processing then issues the value that
/// carries the end user's answer back; presenting that value here is what ends the session.
/// </summary>
/// <param name="authSessionService">Answers which session the user agent currently holds.</param>
/// <param name="subjectTypeConverter">Seals the session's subject the way the hint's client sees it, so a pairwise
/// client's own spelling of the end user is what the hint is compared against.</param>
/// <param name="sessionClients">Answers which clients signed in to the session, for a hint that does not name it.
/// </param>
/// <param name="confirmationStore">Redeems the value that carries the end user's answer back from the page that
/// asked them.</param>
public class ConfirmationValidator(
    IAuthSessionService authSessionService,
    ISubjectTypeConverter subjectTypeConverter,
    ISessionClientRegistry sessionClients,
    ILogoutConfirmationStore confirmationStore) : IEndSessionContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(TenantDefinition tenant, EndSessionValidationContext context)
    {
        // The question is about the session this request would end, so it is asked of that session rather than of
        // the request alone. With no session there is nothing to end and nobody to ask: the processing answers
        // with the redirect and signs nobody out.
        var authSession = await authSessionService.AuthenticateAsync();
        if (authSession == null)
            return null;

        // The end user's own answer, spent here so the same one cannot be sent twice, and asked of this session
        // rather than of the value: a question issued for another session, one already answered and one that
        // expired all lead to the same place below, which is that the end user is asked again.
        if (context.Request.Confirmation is { } confirmation &&
            await confirmationStore.RedeemLogoutConfirmationAsync(tenant, authSession.SessionId, confirmation))
        {
            return null;
        }

        if (await BelongsToTheCurrentSessionAsync(tenant, context, authSession))
            return null;

        // Not a refusal: the request is one this server intends to honour once the end user has answered, so the
        // processing issues the value that asks them. Saying so here, where the decision is made, keeps the
        // question in one place.
        context.ConfirmationRequired = true;
        return null;
    }

    /// <summary>
    /// Decides whether the hint the request carried belongs to <paramref name="authSession"/>: issued to a client of
    /// that session, about its end user.
    /// </summary>
    /// <remarks>
    /// Section 2 leaves a hint whose <c>sid</c> names another session "suspect" and lets the OP decline it; this
    /// library asks the end user instead, which is the outcome the same sentence puts under MUST, and which keeps a
    /// logout working for somebody whose hint is merely stale. The subject travels through the same conversion the
    /// authorization endpoint applies to its own hint, so a pairwise client's pseudonym is compared against the
    /// pseudonym this client would see rather than against the real subject.
    /// <para>
    /// This server states <c>sid</c> only to a client told the session at logout, so the ID tokens of every other
    /// client name no session. Section 2 has the OP accept a hint when "the RP identified by the ID Token's aud claim
    /// and/or sid claim has a current session", so such a hint belongs to the current session when its client is
    /// one this session signed in to, as <see cref="ISessionClientRegistry"/> records, and when it was issued for the
    /// authentication that began this session. The time tells this session apart from another of the same end user
    /// that the same client signed in to, an earlier one or one in another browser, whose ID tokens are otherwise
    /// alike: <c>auth_time</c> is "Time when the End-User authentication occurred" (OpenID Connect Core 1.0 section
    /// 2), stated in whole seconds, and this server writes the session's own time into every ID token it issues. A
    /// hint issued before the end user authenticated again within the same session is therefore asked about, which
    /// section 2 allows, since the OP "SHOULD ask" in every case. With no client recorded for the session, as when
    /// the records have expired, nothing shows the hint's client signed in to it, and the end user is asked.
    /// </para>
    /// </remarks>
    private async Task<bool> BelongsToTheCurrentSessionAsync(
        TenantDefinition tenant,
        EndSessionValidationContext context,
        AuthSession authSession)
    {
        if (context.IdToken is not { Payload: var hint })
            return false;

        // The client is read rather than assumed: the members that resolve it run before this one, and the family
        // is publicly editable, so a host that reorders it finds the request asking for a confirmation instead of
        // skipping one.
        if (context.ClientInfo is not { } clientInfo ||
            hint.Subject is not { } subject ||
            !subjectTypeConverter.Names(tenant, authSession, [subject], clientInfo))
        {
            return false;
        }

        if (hint.SessionId is { } sessionId)
            return string.Equals(sessionId, authSession.SessionId, StringComparison.Ordinal);

        if (hint.AuthenticationTime is not { } authenticationTime ||
            authenticationTime.ToUnixTimeSeconds() != authSession.AuthenticationTime.ToUnixTimeSeconds())
        {
            return false;
        }

        var clients = await sessionClients.GetClientsAsync(tenant, authSession.SessionId);
        return clients.Contains(clientInfo.ClientId, StringComparer.Ordinal);
    }
}
