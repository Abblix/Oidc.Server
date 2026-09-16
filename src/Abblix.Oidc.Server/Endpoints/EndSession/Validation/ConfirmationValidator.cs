// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;

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
/// <param name="confirmationStore">Redeems the value that carries the end user's answer back from the page that
/// asked them.</param>
public class ConfirmationValidator(
    IAuthSessionService authSessionService,
    ISubjectTypeConverter subjectTypeConverter,
    ILogoutConfirmationStore confirmationStore) : IEndSessionContextValidator
{
    /// <inheritdoc />
    public async Task<OidcError?> ValidateAsync(EndSessionValidationContext context)
    {
        // The question is about the session this request would end, so it is asked of that session rather than of
        // the request alone. With no session there is nothing to end and nobody to ask: the processing answers
        // with the redirect and signs nobody out.
        var authSession = await authSessionService.AuthenticateAsync();
        if (authSession == null)
            return null;

        // The end user's own answer, spent here so the same one cannot end a second session, and honoured only
        // for the session it was issued for.
        if (context.Request.Confirmation is { } confirmation)
        {
            var confirmedSessionId = await confirmationStore.RedeemAsync(confirmation);
            if (string.Equals(confirmedSessionId, authSession.SessionId, StringComparison.Ordinal))
                return null;
        }

        if (NamesTheCurrentSession(context, authSession))
            return null;

        // Not a refusal: the request is one this server intends to honour once the end user has answered, so the
        // processing issues the value that asks them. Saying so here, where the decision is made, keeps the
        // question in one place.
        context.ConfirmationRequired = true;
        return null;
    }

    /// <summary>
    /// Decides whether the hint the request carried is about <paramref name="authSession"/>.
    /// </summary>
    /// <remarks>
    /// Section 2 leaves a hint that names another session "suspect" and lets the OP decline it; this library asks
    /// the end user instead, which is the outcome the same sentence puts under MUST, and which keeps a logout
    /// working for somebody whose hint is merely stale.
    /// <para>
    /// The session identifier is compared only when the hint carries one, because OpenID Connect Core 1.0 section 2
    /// makes <c>sid</c> optional in an ID token: a deployment that issues none would otherwise have every logout
    /// stopped for a confirmation. The subject travels through the same conversion the authorization endpoint
    /// applies to its own hint, so a pairwise client's pseudonym is compared against the pseudonym this client
    /// would see rather than against the real subject.
    /// </para>
    /// </remarks>
    private bool NamesTheCurrentSession(EndSessionValidationContext context, AuthSession authSession)
    {
        if (context.IdToken is not { Payload: var hint })
            return false;

        if (hint.SessionId.HasValue() && !string.Equals(hint.SessionId, authSession.SessionId, StringComparison.Ordinal))
            return false;

        // The client is read rather than assumed: the members that resolve it run before this one, and the family
        // is publicly editable, so a host that reorders it finds the request asking for a confirmation instead of
        // skipping one.
        return context.ClientInfo is { } clientInfo &&
               hint.Subject is { } subject &&
               subjectTypeConverter.Names(authSession, [subject], clientInfo);
    }
}
