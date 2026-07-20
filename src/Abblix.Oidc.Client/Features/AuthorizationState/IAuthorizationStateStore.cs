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

namespace Abblix.Oidc.Client.Features.AuthorizationState;

/// <summary>
/// Holds the state of an authorization request between sending the user to the provider and their return.
/// </summary>
public interface IAuthorizationStateStore
{
    /// <summary>
    /// Puts the state aside, keyed by its own <see cref="AuthorizationState.State"/> value.
    /// </summary>
    /// <param name="state">The state to remember.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    Task StoreAsync(AuthorizationState state, CancellationToken cancellationToken = default);

    /// <summary>
    /// Takes the state matching the value the provider echoed, removing it in the same step.
    /// </summary>
    /// <param name="state">The <c>state</c> parameter from the authorization response.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The stored state, or <c>null</c> when nothing matches.</returns>
    /// <remarks>
    /// Taking and removing is one operation on purpose. A stored state is good for exactly one callback: if
    /// reading left it in place, a captured authorization response could be replayed, and each replay would
    /// find its state waiting and look entirely legitimate. Returning null the second time is what makes the
    /// second attempt fail.
    /// </remarks>
    Task<AuthorizationState?> TakeAsync(string state, CancellationToken cancellationToken = default);
}
