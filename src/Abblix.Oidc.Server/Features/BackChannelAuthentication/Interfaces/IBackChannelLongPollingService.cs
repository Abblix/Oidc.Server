// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

/// <summary>
/// Provides signaling infrastructure for CIBA poll mode long-polling, allowing token endpoint requests
/// to wait for authentication completion rather than immediately returning authorization_pending.
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
/// var statusChange = await longPollingSignaler.WaitForStatusChangeAsync(authReqId, timeout, cancellationToken);
///
/// // 3. Meanwhile: User authenticates on device
/// // 4. PollModeCompletionHandler signals the change - approval and refusal alike, and only it: ping
/// //    and push never call NotifyStatusChangeAsync, and poll skips it when no notifier is registered
/// await longPollingSignaler.NotifyStatusChangeAsync(authReqId, BackChannelAuthenticationStatus.Authenticated);
///
/// // 5. Waiting request wakes up, checks storage, returns tokens
/// </code>
/// </remarks>
public interface IBackChannelLongPollingService
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
    /// <para>
    /// Call this whenever a request leaves the Pending state, and note which of those transitions are
    /// yours to signal rather than the library's.
    /// </para>
    /// <list type="bullet">
    ///   <item><strong>Authenticated and Denied through the completion handler</strong> are signalled by
    ///   the handler itself, in poll and ping alike - a host that completes through
    ///   <see cref="IAuthenticationCompletionHandler"/> needs nothing more. Ping is on that list because
    ///   a ping client polls the token endpoint too, and the long-poll gate does not read the delivery
    ///   mode; push is not, because its token endpoint refuses the client outright, so no push client is
    ///   ever a waiter.</item>
    ///   <item><strong>A status the host writes to storage itself</strong> is the host's to signal. The
    ///   denial pattern documented on <see cref="IUserDeviceAuthenticationHandler"/> is exactly this
    ///   case: it updates the stored record directly, so nothing in the library sees the change and a
    ///   waiter sleeps until its own window runs out.</item>
    ///   <item><strong>Expiry</strong> is signalled by nobody, and a waiter is NOT told about it: when
    ///   its window runs out it is answered <c>authorization_pending</c>, and it learns the request
    ///   expired on the poll after that, from the record being gone. The grant handler does compare the
    ///   stored expiry against the clock and remove the record, so there is a place a signal could be
    ///   sent from; nothing sends one today.</item>
    /// </list>
    /// <para>
    /// It's safe to call this even if no requests are waiting - it's a no-op in that case.
    /// </para>
    /// </remarks>
    Task NotifyStatusChangeAsync(
        string authenticationRequestId,
        BackChannelAuthenticationStatus newStatus);
}
