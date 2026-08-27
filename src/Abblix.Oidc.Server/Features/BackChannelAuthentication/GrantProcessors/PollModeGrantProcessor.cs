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
/// The stored request is claimed on retrieval - read and removed in one protocol - so that a poll told it
/// took the request is the only poll that can be told so. That narrows the window in which two polls both
/// issue rather than closing it; the method below says what its refusal covers.
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
    /// Removes the authentication request from storage through the store's claim protocol and returns its
    /// authorized grant.
    /// A removal that does not come back with the request is answered <c>invalid_grant</c> rather than
    /// re-issuing tokens. That is the right answer and not a diagnosis: the request comes back only when
    /// this caller ran the protocol to the end with its own claim still in the store, and every way short
    /// of that is one answer. A store fault after the removal is not among them at all - it raises past
    /// this method.
    /// </summary>
    public async Task<Result<AuthorizedGrant, OidcError>> ProcessAuthenticatedRequestAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request)
    {
        // Removed through the store's claim protocol, which is what keeps two polls from both coming back
        // with the grant - the duplicate token issuance this exists to stop, and it holds however many
        // processes are polling. The per-key gate around it buys something else: a contended key that
        // would otherwise end with NEITHER poll told it took the request. Neither closes the window in
        // which a write lands between the read and the removal. Null does not say WHY - see the storage
        // contract.
        var removedRequest = await storage.TryRemoveAsync(authenticationRequestId);

        if (removedRequest == null)
        {
            // Not necessarily a competitor: the claim can expire mid-protocol on a single caller with
            // nobody to lose to, and the receiver is told the same thing either way. A store fault after
            // the removal never reaches here - it raises, and the receiver gets no result at all.
            return new OidcError(
                ErrorCodes.InvalidGrant,
                "The authentication request has already been used");
        }

        return removedRequest.AuthorizedGrant;
    }
}
