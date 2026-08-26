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
/// Handles CIBA poll mode token retrieval at the token endpoint.
/// In poll mode, clients repeatedly poll until authentication completes.
/// The stored request is removed immediately on retrieval to prevent duplicate issuance.
/// Uses atomic try-remove operation to prevent race conditions.
/// </summary>
/// <param name="storage">Storage for backchannel authentication requests.</param>
public class PollModeGrantProcessor(IBackChannelRequestStorage storage)
    : IBackChannelGrantProcessor
{
    /// <summary>
    /// Poll mode clients are expected to poll the token endpoint, so this always returns <c>null</c> (no error).
    /// </summary>
    public OidcError? ValidateTokenEndpointAccess() => null;

    /// <summary>
    /// Atomically removes the authentication request from storage and returns its authorized grant.
    /// A removal that does not come back with the request is answered <c>invalid_grant</c> rather than
    /// re-issuing tokens. That is the right answer and not a diagnosis: a competitor produces it, and so
    /// does a claim that expired mid-protocol or a store call that failed after the removal.
    /// </summary>
    public async Task<Result<AuthorizedGrant, OidcError>> ProcessAuthenticatedRequestAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request)
    {
        // Removed atomically so two polls cannot both come back with the grant, which is the duplicate
        // token issuance this exists to stop. Null does not say WHY - see the storage contract.
        var removedRequest = await storage.TryRemoveAsync(authenticationRequestId);

        if (removedRequest == null)
        {
            // Not necessarily a competitor: the claim can expire mid-protocol and a store call after the
            // removal can fail, both on a single caller. The receiver gets the same answer either way.
            return new OidcError(
                ErrorCodes.InvalidGrant,
                "The authentication request has already been used");
        }

        return removedRequest.AuthorizedGrant;
    }
}
