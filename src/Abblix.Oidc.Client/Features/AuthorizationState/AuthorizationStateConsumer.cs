// Abblix OIDC Client Library
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

namespace Abblix.Oidc.Client.Features.AuthorizationState;

/// <summary>
/// Consumes the stored state for an authorization response, turning a miss into a typed refusal.
/// </summary>
/// <param name="store">Where the state was put aside when the request was built.</param>
internal sealed class AuthorizationStateConsumer(IAuthorizationStateStore store) : IAuthorizationStateConsumer
{
    public async Task<AuthorizationState> ConsumeAsync(
        string? state, CancellationToken cancellationToken = default)
    {
        // No state to look up. This client sends one on every request, so its absence is not an
        // expired login that can be restarted - it is a response that never belonged to us.
        if (string.IsNullOrEmpty(state))
        {
            throw new AuthorizationStateException(
                AuthorizationStateFailure.Missing,
                "The authorization response carried no state, but this client sends one on every request.");
        }

        // Take-and-remove: the second attempt on the same state finds nothing, which is what makes a
        // replayed authorization response fail rather than look legitimate a second time.
        var stored = await store.TakeAsync(state, cancellationToken);
        if (stored is null)
        {
            throw new AuthorizationStateException(
                AuthorizationStateFailure.Unknown,
                "The authorization response names a state this client is not holding. The login may have "
                + "expired, its response may already have been handled, or the state was never issued - "
                + "which of these is deliberately not distinguished.");
        }

        return stored;
    }
}
