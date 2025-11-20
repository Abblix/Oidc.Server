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

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

/// <summary>
/// Provides a mechanism for notifying waiting long-polling requests when backchannel authentication
/// status changes. This enables efficient implementation of CIBA long-polling mode where token requests
/// are held open until authentication completes or timeout occurs.
/// </summary>
/// <remarks>
/// <para>
/// This interface supports the optional long-polling feature of CIBA poll mode. When long-polling is enabled,
/// token endpoint requests for pending authentication requests are held open (up to a timeout) instead of
/// immediately returning authorization_pending. When the user completes authentication, all waiting requests
/// for that auth_req_id are notified and can immediately return the tokens.
/// </para>
///
/// <para><strong>Benefits of Long-Polling:</strong></para>
/// <list type="bullet">
///   <item>Reduced latency: Tokens returned immediately when authentication completes (0-1 second vs 0-5 seconds)</item>
///   <item>Reduced server load: Fewer HTTP requests (1-4 per minute vs 12 per minute with 5-second polling)</item>
///   <item>Better user experience: Faster token delivery without constant polling overhead</item>
/// </list>
///
/// <para><strong>Implementation Patterns:</strong></para>
/// <list type="bullet">
///   <item>In-memory: Use events/TaskCompletionSource for single-server deployments</item>
///   <item>Distributed: Use Redis Pub/Sub, SignalR, or message queue for multi-server deployments</item>
/// </list>
///
/// <para><strong>Example Flow:</strong></para>
/// <code>
/// // 1. Client requests token (status = Pending)
/// // 2. Server holds connection and waits
/// var statusChange = await statusNotifier.WaitForStatusChangeAsync(authReqId, timeout, cancellationToken);
///
/// // 3. Meanwhile: User authenticates on device
/// // 4. BackChannelAuthenticationNotifier signals change
/// await statusNotifier.NotifyStatusChangeAsync(authReqId, BackChannelAuthenticationStatus.Authenticated);
///
/// // 5. Waiting request wakes up, checks storage, returns tokens
/// </code>
/// </remarks>
public interface IBackChannelAuthenticationStatusNotifier
{
    /// <summary>
    /// Waits for a status change notification for the specified authentication request.
    /// Returns immediately if a notification is received, or after timeout if no change occurs.
    /// </summary>
    /// <param name="authenticationRequestId">The unique identifier of the authentication request to wait for.</param>
    /// <param name="timeout">Maximum time to wait for a status change.</param>
    /// <param name="cancellationToken">Cancellation token to abort the wait operation.</param>
    /// <returns>
    /// A task that completes when either:
    /// - A status change notification is received (returns true)
    /// - The timeout expires (returns false)
    /// - The cancellation token is triggered (throws OperationCanceledException)
    /// </returns>
    /// <remarks>
    /// This method does NOT return the new status - it only signals that a change occurred.
    /// The caller must retrieve the updated status from storage.
    ///
    /// Multiple callers can wait for the same auth_req_id simultaneously (e.g., if client retries).
    /// All waiters will be notified when status changes.
    /// </remarks>
    Task<bool> WaitForStatusChangeAsync(
        string authenticationRequestId,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Notifies all waiting requests that the authentication status has changed for the specified request.
    /// This immediately releases any long-polling token requests waiting for this auth_req_id.
    /// </summary>
    /// <param name="authenticationRequestId">The unique identifier of the authentication request that changed.</param>
    /// <param name="newStatus">The new authentication status (for logging/diagnostics only).</param>
    /// <returns>A task that completes when all waiting requests have been notified.</returns>
    /// <remarks>
    /// This should be called whenever authentication status changes from Pending to:
    /// - Authenticated (user approved)
    /// - Denied (user rejected)
    /// - Expired (timeout occurred)
    ///
    /// It's safe to call this even if no requests are waiting - it's a no-op in that case.
    /// </remarks>
    Task NotifyStatusChangeAsync(
        string authenticationRequestId,
        BackChannelAuthenticationStatus newStatus);
}
