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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Builds the context an authorization request's codes and tokens carry, from what the end user granted and as
/// the consent backstop leaves it.
/// </summary>
/// <param name="consentConstraintEnforcer">Holds the granted set to the request.</param>
internal sealed class AuthorizationContextBuilder(IConsentConstraintEnforcer consentConstraintEnforcer)
{
    /// <summary>
    /// Builds the context the issued codes and tokens carry, from what the end user granted, or the refusal
    /// the consent backstop answers with.
    /// </summary>
    public async Task<Result<AuthorizationContext, OidcError>> BuildAsync(
        ValidAuthorizationRequest request,
        UserConsents userConsents,
        JsonArray? requestedDetails)
    {
        var model = request.Model;

        // Defense-in-depth backstop: the IUserConsentsProvider contract permits a NARROWER grant
        // than the request, never a broader one. Assert that invariant before the granted set
        // reaches the issued token. What it checks itself: scopes and resources against the request,
        // and authorization_details by type and shape - a granted scope, resource or type the request
        // did not carry is a host-side defect and throws. What it leaves to each type's validator,
        // handed the requested entries of its type: whether a granted entry stays within them (an
        // amount, an account), which RFC 9396 section 6.1 says only the type's definition can decide.
        // A validator refusing one is answered with access_denied. Symmetric with the strictly
        // narrowing-only TokenAuthorizationContextEvaluator at the token endpoint.
        // What the end user granted, read before the backstop runs. It is a seam of its own and it is
        // handed the granted set to check, so the scopes and resources the token carries are taken from
        // the answer rather than from what the check left behind.
        ScopeDefinition[] grantedScopes = [..userConsents.Granted.Scopes];
        ResourceDefinition[] grantedResources = [..userConsents.Granted.Resources];

        // Handed what was asked for rather than what the provider left behind: the backstop measures the
        // granted set against the request, and the provider it is policing can reach that array.
        var enforcement = await consentConstraintEnforcer.EnforceAsync(
            request with { AuthorizationDetails = requestedDetails },
            userConsents.Granted,
            CancellationToken.None);

        if (!enforcement.TryGetSuccess(out var enforcedAuthorizationDetails))
            return enforcement.GetFailure();

        // C2 (PR #135 review): the JsonArray reference passed to the consent provider and the
        // one placed on AuthorizationContext travel through System.Text.Json on the way to the
        // issued JWT. If a host's IUserConsentsProvider impl parents the borrowed array as a
        // child of its own DTO, the second serialise will throw because the JsonNode is parented
        // twice. DeepClone defensively on the boundary so the two consumers each see independent
        // trees -- matches the DeepClone discipline applied elsewhere (ApplyTo, resolvers).
        var sourceAd = enforcedAuthorizationDetails is { Count: > 0 } ? enforcedAuthorizationDetails : requestedDetails;
        var emittedAuthorizationDetails = sourceAd is { Count: > 0 }
            ? (JsonArray?)sourceAd.DeepClone()
            : null;

        // Build an authorization context containing necessary data like client ID, scopes, and claims.
        // The authorization context is used to carry the granted scopes, resources and other key details through
        // the flow.
        return new AuthorizationContext(
            request.ClientInfo.ClientId,
            grantedScopes,
            grantedResources,
            model.Claims)
        {
            RedirectUri = model.RedirectUri,
            Nonce = model.Nonce,
            // An empty code_challenge, which a request object carries as written, is no challenge: PkceValidator
            // treats it as absent, and so does the code exchange
            CodeChallenge = model.CodeChallenge.HasValue() ? model.CodeChallenge : null,
            CodeChallengeMethod = model.CodeChallengeMethod,
            ProofKeyThumbprint = model.ProofKeyThumbprint,
            AuthorizationDetails = emittedAuthorizationDetails,
        };
    }

}
