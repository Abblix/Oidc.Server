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
    /// The token to present right now. With authentication configured it is the minted one and nothing
    /// else - configuring authentication REPLACES a host-supplied token, so a stale value left in
    /// configuration (the dead agent-rendered token this feature exists to retire) is never presented while
    /// the first login is still in flight. Without authentication it is the host-supplied token, read
    /// through the monitor so a rotation delivered by configuration reload takes effect per request.
    /// Whitespace normalizes to null, so an env var defined but empty reads as "no token" everywhere.
    /// </summary>
    public string? Current
    {
        get
        {
            if (AuthenticationConfigured)
                return _minted;

            var hostToken = options.CurrentValue.Token;
            return string.IsNullOrWhiteSpace(hostToken) ? null : hostToken;
        }
    }

    /// <summary>Whether the package logs in itself, which is what makes the first login worth waiting for.</summary>
    public bool AuthenticationConfigured => options.CurrentValue.Authentication is not null;

    /// <summary>
    /// Completes when the first login has published a token, and fails once the lifecycle service stops
    /// without ever publishing one. Callers that need a token before the lifecycle service has produced one
    /// await this instead of racing it - whichever consumer reaches Vault first waits for the login rather
    /// than failing without a token. The login itself runs under the lifecycle service's own lifetime, never
    /// under an awaiting caller's cancellation, so one caller giving up cannot kill the login every other
    /// caller is waiting for.
    /// </summary>
    public Task FirstLoginCompleted => _firstLogin.Task;

    /// <summary>Publishes a token minted by login or returned by renewal.</summary>
    public void Publish(string token)
    {
        _minted = token;
        _firstLogin.TrySetResult();
    }

    /// <summary>
    /// Fails the first-login promise when the lifecycle stops without having published a token, so a request
    /// waiting on it fails now with a message naming the cause, instead of burning its whole client timeout
    /// against a login nobody is performing. A no-op after the first publish.
    /// </summary>
    public void AbandonFirstLogin()
        => _firstLogin.TrySetException(new InvalidOperationException(
            $"The Vault token lifecycle stopped before the first login completed, so no token will arrive; " +
            $"see the {nameof(TokenLifecycleService)} log for why it stopped."));
}
