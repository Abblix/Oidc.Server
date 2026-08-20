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
/// Tokens are removed from storage immediately after retrieval to prevent duplicate issuance.
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
    /// If a concurrent request already consumed the entry, returns an <c>invalid_grant</c> error
    /// to prevent duplicate token issuance.
    /// </summary>
    public async Task<Result<AuthorizedGrant, OidcError>> ProcessAuthenticatedRequestAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request)
    {
        // Atomically remove from storage to prevent race condition where concurrent requests
        // could both retrieve the same grant before removal (duplicate token issuance vulnerability)
        // If another request already removed it, this returns null
        var removedRequest = await storage.TryRemoveAsync(authenticationRequestId);

        if (removedRequest == null)
        {
            // Request was already retrieved by another concurrent request
            return new OidcError(
                ErrorCodes.InvalidGrant,
                "The authentication request has already been used");
        }

        return removedRequest.AuthorizedGrant;
    }
}
