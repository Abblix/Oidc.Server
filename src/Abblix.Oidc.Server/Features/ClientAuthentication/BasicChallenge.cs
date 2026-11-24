// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

/// <summary>
/// Whether a refusal of client authentication answers with a <c>WWW-Authenticate: Basic</c> challenge, the one answer
/// every endpoint authenticating clients gives.
/// </summary>
/// <remarks>
/// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 3.2.4: "If the client attempted to authenticate via the Authorization
/// request header field ..., the authorization server MUST respond with a 401 (Unauthorized) status code and include
/// the WWW-Authenticate response header field ... matching the authentication scheme used by the client. Client
/// authentication methods that do not use an HTTP authentication scheme have no corresponding challenge". Basic is the
/// one HTTP scheme the server authenticates clients by, so the challenge is owed to a request that used it, and to no
/// other: such a request is answered with its endpoint's own status and no challenge, since RFC 9110 section 15.5.2
/// has a 401 "send a WWW-Authenticate header field containing at least one challenge". The answer reads the request
/// alone, so it says nothing about whether the client it names exists or how that client authenticates.
/// </remarks>
internal static class BasicChallenge
{
    /// <summary>
    /// Whether a refusal of <paramref name="request"/> answers with the Basic challenge: the request authenticated by
    /// HTTP Basic.
    /// </summary>
    /// <param name="request">The client authentication the request carries.</param>
    public static bool IsOwed(ClientRequest request)
        => request.AuthorizationHeader.HasScheme(TokenTypes.Basic);

    /// <summary>
    /// The <c>invalid_client</c> refusal of <paramref name="request"/>, carrying whether the Basic challenge is owed.
    /// </summary>
    /// <param name="request">The client authentication the request carries.</param>
    /// <param name="description">What the refusal says.</param>
    public static OidcError InvalidClient(ClientRequest request, string description)
        => new(ErrorCodes.InvalidClient, description) { BasicChallengeOwed = IsOwed(request) };
}
