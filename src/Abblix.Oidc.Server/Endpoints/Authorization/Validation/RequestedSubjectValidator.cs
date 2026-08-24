// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Records the end users a <c>claims</c> request will accept for <c>sub</c>, so the endpoint can honour them
/// when it chooses a session.
/// </summary>
/// <remarks>
/// This is the second way of asking what <c>id_token_hint</c> asks, and OpenID Connect Core 1.0 Section
/// 3.1.2.2 states them as one requirement: "If the <c>sub</c> (subject) Claim is requested with a specific
/// value for the ID Token, the Authorization Server MUST only send a positive response if the End-User
/// identified by that <c>sub</c> value has an active session with the Authorization Server or has been
/// Authenticated as a result of the request. The Authorization Server MUST NOT reply with an ID Token or
/// Access Token for a different user, even if they have an active session with the Authorization Server. Such
/// a request can be made either using an <c>id_token_hint</c> parameter or by requesting a specific Claim
/// Value as described in Section 5.5.1, if the <c>claims</c> parameter is supported by the implementation."
/// <para>
/// The condition attached to that MUST is met here rather than left open: the discovery document advertises
/// <c>claims_parameter_supported</c>, so a client is entitled to expect the parameter to decide something.
/// What makes a request name somebody lives in <see cref="RequestedClaimsExtensions.RequestedSubjects"/>,
/// shared with the decoupled endpoint that accepts the same parameter without a browser.
/// </para>
/// <para>
/// Runs beside <see cref="IdTokenHintValidator"/> and after the validators that resolve the redirect URI and
/// the response mode, for the same reason: its refusals are the kind RFC 6749 Section 4.1.2.1 says the client
/// must be told about by redirection, and before those there is nowhere to tell it.
/// </para>
/// </remarks>
public class RequestedSubjectValidator : SyncAuthorizationContextValidatorBase
{
    /// <inheritdoc />
    protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
    {
        var requested = context.Request.Claims.RequestedSubjects();
        if (requested.TryGetFailure(out var reason))
            return context.InvalidRequest(reason);

        context.RequestedSubjects = requested.GetSuccess();
        return null;
    }
}
