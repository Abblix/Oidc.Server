// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.GrantProcessors;

/// <summary>
/// Handles CIBA ping mode token retrieval at the token endpoint.
/// In ping mode, the server notifies the client, then the client makes a single token request.
/// The auth_req_id is single-use - CIBA Core 1.0 Section 10.1.1: "Once redeemed for a successful token
/// response, the auth_req_id value that was used is no longer valid" - so the grant is removed from
/// storage on retrieval, identically to poll mode, whose token response the same section defines.
/// </summary>
/// <param name="storage">Storage for backchannel authentication requests.</param>
public class PingModeGrantProcessor(IBackChannelRequestStorage storage)
    : IBackChannelGrantProcessor
{
    /// <summary>
    /// Ping mode clients are allowed to call the token endpoint after the ping notification arrives,
    /// so this always returns <c>null</c> (no error).
    /// </summary>
    public OidcError? ValidateTokenEndpointAccess() => null;

    /// <summary>
    /// Removes the authentication request from storage under the store's per-key gate and returns its
    /// authorized grant.
    /// Because the auth_req_id can be used only once (CIBA Core 1.0 Section 10.1.1), a retrieval that
    /// does not come back with the request is rejected with <c>invalid_grant</c> rather than re-issuing
    /// tokens. Which is the right answer to give the caller, and not a diagnosis: a second retrieval
    /// produces it, and so does a claim that expired mid-protocol on a single caller with no competitor.
    /// A store call that fails after the removal produces neither - it raises, and the caller is handed
    /// an exception instead of a result.
    /// </summary>
    public async Task<Result<AuthorizedGrant, OidcError>> ProcessAuthenticatedRequestAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request)
    {
        var removedRequest = await storage.TryRemoveAsync(authenticationRequestId);

        if (removedRequest == null)
        {
            return new OidcError(
                ErrorCodes.InvalidGrant,
                "The authentication request has already been used");
        }

        return removedRequest.AuthorizedGrant;
    }
}
