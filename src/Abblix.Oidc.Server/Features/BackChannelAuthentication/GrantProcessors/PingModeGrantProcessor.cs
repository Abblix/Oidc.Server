// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.GrantProcessors;

/// <summary>
/// Handles CIBA ping mode token retrieval at the token endpoint.
/// In ping mode, the server notifies the client, then the client makes a single token request.
/// The auth_req_id is single-use (CIBA Core 1.0 Section 7.3), so the grant is removed from storage
/// on retrieval - identically to poll mode (Section 10.1.1 defines their token responses the same).
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
    /// Atomically removes the authentication request from storage and returns its authorized grant.
    /// Because the auth_req_id can be used only once (CIBA Core 1.0 Section 7.3), a second retrieval
    /// - or a concurrent one that lost the race - finds nothing and is rejected with
    /// <c>invalid_grant</c> rather than re-issuing tokens.
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
