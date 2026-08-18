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

using Microsoft.Extensions.Options;

namespace Abblix.Jwt.Vault;

/// <summary>
/// The one place the current Vault token lives: the token the lifecycle service minted by logging in, or,
/// until it has minted one, whatever the host supplied through options.
/// </summary>
/// <remarks>
/// A rotating credential is state, not configuration, so it is held here as a field rather than pushed back
/// through the options pipeline - re-running every configure delegate and validator to move one string would
/// be the heavier and the more surprising machinery. The host-supplied token stays behind the options
/// monitor, so a token rotated through configuration reload keeps working exactly as it did before this type
/// existed. The field is volatile and the string immutable, which is all the synchronization a
/// read-mostly single reference needs.
/// </remarks>
internal sealed class TokenSource(IOptionsMonitor<VaultTransitOptions> options)
{
    private readonly TaskCompletionSource _firstLogin = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private volatile string? _minted;

    /// <summary>
    /// The token to present right now: the minted one once a login succeeded, the host-supplied one before
    /// that, null when there is neither.
    /// </summary>
    public string? Current => _minted ?? options.CurrentValue.Token;

    /// <summary>Whether the package logs in itself, which is what makes the first login worth waiting for.</summary>
    public bool AuthenticationConfigured => options.CurrentValue.Authentication is not null;

    /// <summary>
    /// Completes when the first login has published a token. Callers that need a token before the lifecycle
    /// service has produced one await this instead of racing it - whichever consumer reaches Vault first
    /// waits for the login rather than failing without a token. The login itself runs under the lifecycle
    /// service's own lifetime, never under an awaiting caller's cancellation, so one caller giving up cannot
    /// kill the login every other caller is waiting for.
    /// </summary>
    public Task FirstLoginCompleted => _firstLogin.Task;

    /// <summary>Publishes a token minted by login or returned by renewal.</summary>
    public void Publish(string token)
    {
        _minted = token;
        _firstLogin.TrySetResult();
    }
}
