// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using StoredRequest = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationRequest;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Handles the authorization process for backchannel authentication requests under the Client-Initiated Backchannel
/// Authentication (CIBA) grant type.
/// This handler validates the token request based on the backchannel authentication flow, ensuring
/// that the client is authorized and that the user has been authenticated before tokens are issued.
/// Supports both short-polling (immediate response) and long-polling (holds connection until auth completes).
/// </summary>
/// <param name="storage">Service for storing and retrieving backchannel authentication requests.</param>
/// <param name="pollSchedule">Holds the instant before which this request's client is told to slow
/// down, under a key of its own so noting it cannot overwrite the authentication.</param>
/// <param name="keyFactory">Names the key that instant lives under.</param>
/// <param name="timeProvider">Provides access to the current time.</param>
/// <param name="options">Configuration options for backchannel authentication including long-polling settings.</param>
/// <param name="serviceProvider">Resolves the mode-specific grant processors and the redeemer that judges an
/// authenticated request before it is exchanged for tokens. The redeemer is internal and registered by
/// <c>AddBackChannelAuthentication</c>, so a provider built without that call cannot construct the handler.</param>
/// <param name="statusNotifier">Notifier for long-polling status changes (null if long-polling disabled).</param>
public class BackChannelAuthenticationGrantHandler(
    IBackChannelRequestStorage storage,
    IPollScheduleStore pollSchedule,
    IEntityStorageKeyFactory keyFactory,
    TimeProvider timeProvider,
    IOptions<OidcOptions> options,
    IServiceProvider serviceProvider,
    IBackChannelLongPollingService? statusNotifier = null) : IAuthorizationGrantHandler
{
    // Resolved rather than injected: the redeemer is internal, and a public constructor cannot name it.
    private readonly BackChannelGrantRedeemer _redeemer =
        serviceProvider.GetRequiredService<BackChannelGrantRedeemer>();

    /// <summary>
    /// Specifies the grant types supported by this handler, specifically the "CIBA" (Client-Initiated Backchannel
    /// Authentication) grant type.
    /// This property ensures that the handler is only invoked for the specific grant type it supports.
    /// </summary>
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.Ciba; }
    }

    /// <summary>
    /// Processes the authorization request by verifying the authentication request ID and checking the status of the
    /// associated backchannel authentication request. Supports both short-polling (immediate response) and optional
    /// long-polling (holds connection until authentication completes or timeout).
    /// </summary>
    /// <remarks>
    /// <para><strong>Behavior by Authentication Status:</strong></para>
    /// <list type="bullet">
    ///   <item><term>Authenticated:</term> Returns authorized grant and removes from storage (poll mode only)</item>
    ///   <item><term>Pending (short-polling):</term> Immediately returns authorization_pending error</item>
    ///   <item><term>Pending (long-polling):</term> Waits for status change notification up to configured timeout,
    ///   then re-checks storage to return grant or appropriate error</item>
    ///   <item><term>Denied:</term> Returns access_denied error</item>
    ///   <item><term>Expired/Not Found:</term> Returns expired_token error</item>
    ///   <item><term>Rate Limited:</term> Returns slow_down when asked before the instant this request's client was given</item>
    /// </list>
    /// <para>
    /// Long-polling reduces latency (0-1s vs 0-5s) and server load (1-4 req/min vs 12 req/min) by holding the
    /// connection open until authentication completes instead of requiring repeated polling.
    /// </para>
    /// </remarks>
    /// <param name="request">The token request containing the authentication request ID and other parameters.</param>
    /// <param name="clientInfo">Information about the client making the request, used to validate client identity
    /// and determine token delivery mode (poll/ping/push).</param>
    /// <returns>
    /// Either an authorized grant if authentication succeeded, or an error indicating why the request failed
    /// (authorization_pending, access_denied, expired_token, slow_down, or invalid_grant).
    /// </returns>
    /// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
    public async Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo, CancellationToken cancellationToken)
    {
        // RFC 6749 section 5.2: a missing required parameter is the caller's protocol error (invalid_request),
        // not a server fault - the previous throw-on-access surfaced it as HTTP 500.
        if (!request.AuthenticationRequestId.HasValue())
        {
            return ErrorFactory.MissingParameter(TokenRequest.Parameters.AuthenticationRequestId);
        }

        // Both of these decide from the client's own registered metadata and need nothing from storage, so they
        // run before the lookup. Ordering them the other way let a request that is refused on configuration
        // grounds alone still cost a storage round trip, which hands an authenticated client a cheap way to
        // make the server work: the refusal is free to produce and the lookup is not.
        if (ResolveProcessor(clientInfo) is not { } processor)
            return NotConfiguredForDelivery();

        // Validate that the client is allowed to access the token endpoint for this mode
        var accessError = processor.ValidateTokenEndpointAccess();
        if (accessError != null)
        {
            return accessError;
        }

        // Try to retrieve the corresponding backchannel authentication request from storage
        var authenticationRequest = await storage.TryGetAsync(request.AuthenticationRequestId);

        // Determine the outcome of the authorization based on the state of the backchannel authentication request
        return authenticationRequest switch
        {
            // CIBA Core section 11: "If the auth_req_id is invalid or was issued to another Client, an
            // invalid_grant error MUST be returned". One evicted on expiry cannot be told from one never issued.
            null => new OidcError(ErrorCodes.InvalidGrant, "The authentication request is not recognized"),

            // If the client making the request is not the same as the one that initiated the authentication
            // This validation MUST occur before any status-specific processing for security
            { AuthorizedGrant.Context.ClientId: var clientId } when clientId != clientInfo.ClientId
                => new OidcError(ErrorCodes.InvalidGrant, "The authentication request was issued to another client"),

            // If the user has been authenticated, process mode-specific token retrieval
            { Status: BackChannelAuthenticationStatus.Authenticated } authenticated
                => await _redeemer.RedeemAsync(
                    request.AuthenticationRequestId, authenticated, clientInfo, processor),

            // If the user has not yet been authenticated and the request is still pending, either
            // tell a client that asked early to slow down, or wait for a status change (long
            // polling) and otherwise answer immediately
            { Status: BackChannelAuthenticationStatus.Pending } pendingRequest
                => await HandlePendingRequestAsync(
                    request.AuthenticationRequestId, pendingRequest, clientInfo, cancellationToken),

            // If the user denied the authentication request, return an error indicating access is denied
            { Status: BackChannelAuthenticationStatus.Denied }
                => new OidcError(ErrorCodes.AccessDenied, "The authorization request was denied."),

            _ => throw new InvalidOperationException(
                $"The authentication request status is unexpected: {authenticationRequest.Status}.")
        };
    }

    /// <summary>
    /// Handles pending authentication requests with optional long-polling support.
    /// Notes when the client may ask again, then attempts long-polling if enabled,
    /// otherwise returns authorization_pending immediately.
    /// </summary>
    /// <remarks>
    /// The next-poll instant lives under a key of its own, so noting it writes nothing the
    /// authentication owns. An earlier version of this method wrote the whole request back, and a
    /// completion that landed between its read and that write was overwritten: the user had
    /// authenticated, and the client was told to keep waiting until the request expired. The remark
    /// here called that race benign, which held for the race it described - two polls overwriting
    /// each other's instant, both writing about the same moment - and not for the one that mattered.
    /// <para>
    /// Two polls can still overwrite each other's instant, and that stays harmless for exactly the
    /// reason the old remark gave.
    /// </para>
    /// </remarks>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="authenticationRequest">The pending authentication request to update.</param>
    /// <param name="clientInfo">Client information for determining token delivery mode.</param>
    /// <param name="cancellationToken">Abandons the wait when the caller stops waiting.</param>
    /// <returns>Either an authorized grant if authentication completed during long-polling, or authorization_pending error.</returns>
    private async Task<Result<AuthorizedGrant, OidcError>> HandlePendingRequestAsync(
        string authenticationRequestId,
        Features.BackChannelAuthentication.BackChannelAuthenticationRequest authenticationRequest,
        ClientInfo clientInfo,
        CancellationToken cancellationToken)
    {
        // Calculate remaining time before expiration
        var expiresIn = authenticationRequest.ExpiresAt - timeProvider.GetUtcNow();
        if (expiresIn <= TimeSpan.Zero)
        {
            // Request has expired, remove it
            await storage.TryRemoveAsync(authenticationRequestId);
            return new OidcError(ErrorCodes.ExpiredToken, "The authentication request has expired");
        }

        // The instant before which this client is told to slow down, under a key of its own.
        // Absence means it may ask now.
        var pollingInterval = options.Value.BackChannelAuthentication.PollingInterval;
        var pollKey = keyFactory.BackChannelAuthenticationNextPollKey(authenticationRequestId);
        var nextPollAt = await pollSchedule.TryGetNextPollAtAsync(pollKey);

        var now = timeProvider.GetUtcNow();
        var askedEarly = nextPollAt is { } earliest && now < earliest;

        // The authentication may have completed since the read this answer is decided on. Reading once
        // more is about the answer being current, not about keeping that completion safe: nothing on this
        // path writes the request, so there is nothing for a poll to overwrite. The same method the long
        // poll hands its re-read to, so a client that waits and a client that asks again are answered by
        // one piece of code.
        if (await storage.TryGetAsync(authenticationRequestId) is
            { Status: not BackChannelAuthenticationStatus.Pending } advanced)
        {
            return await ProcessUpdatedRequest(
                advanced, authenticationRequestId, clientInfo);
        }

        // Asking early pushes the instant further out rather than resetting it from now: a client
        // that ignores the interval does not get a fresh one. Bounded by the request's own expiry, which
        // changes no answer a client can receive - the expiry check above runs first - and keeps the
        // stored instant inside the life of what it describes.
        var pushedTo = (askedEarly ? nextPollAt!.Value : now) + pollingInterval;
        await pollSchedule.SetNextPollAtAsync(
            pollKey,
            pushedTo < authenticationRequest.ExpiresAt ? pushedTo : authenticationRequest.ExpiresAt,
            expiresIn);

        if (askedEarly)
        {
            return new OidcError(
                ErrorCodes.SlowDown,
                "The token endpoint was polled before the minimum interval elapsed; reduce the polling rate.");
        }

        if (options.Value.BackChannelAuthentication.UseLongPolling && statusNotifier != null
            && await TryLongPollingAsync(authenticationRequestId, clientInfo, cancellationToken)
                is { } result)
        {
            return result;
        }

        return new OidcError(
            ErrorCodes.AuthorizationPending,
            "The authorization request is still pending. " +
            "The polling interval must be increased by at least 5 seconds for all subsequent requests.");
    }

    /// <summary>
    /// Attempts long-polling for status change notification.
    /// </summary>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="clientInfo">Client information for determining token delivery mode.</param>
    /// <param name="cancellationToken">Abandons the wait when the caller stops waiting.</param>
    /// <returns>
    /// The result of processing the updated request if status changed, or null if timeout occurred.
    /// Null indicates the caller should return authorization_pending error.
    /// </returns>
    private async Task<Result<AuthorizedGrant, OidcError>?> TryLongPollingAsync(
        string authenticationRequestId,
        ClientInfo clientInfo,
        CancellationToken cancellationToken)
    {
        var statusChanged = await statusNotifier!.WaitForStatusChangeAsync(
            authenticationRequestId,
            options.Value.BackChannelAuthentication.LongPollingTimeout,
            cancellationToken);

        if (!statusChanged)
        {
            return null;
        }

        var updatedRequest = await storage.TryGetAsync(authenticationRequestId);
        return await ProcessUpdatedRequest(
            updatedRequest, authenticationRequestId, clientInfo);
    }

    /// <summary>
    /// Processes the updated authentication request after status change notification.
    /// Handles Authenticated, Denied, and Expired states appropriately.
    /// </summary>
    /// <param name="updatedRequest">The updated authentication request from storage, or null if expired.</param>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="clientInfo">Client information for determining token delivery mode.</param>
    /// <returns>Either an authorized grant, access denied error, expired token error, or authorization_pending.</returns>
    private async Task<Result<AuthorizedGrant, OidcError>> ProcessUpdatedRequest(
        Features.BackChannelAuthentication.BackChannelAuthenticationRequest? updatedRequest,
        string authenticationRequestId,
        ClientInfo clientInfo)
    {
        // Validate client ownership before processing (security critical)
        if (updatedRequest?.AuthorizedGrant.Context.ClientId != clientInfo.ClientId)
        {
            return new OidcError(ErrorCodes.InvalidGrant, "The authentication request was issued to another client");
        }

        if (ResolveProcessor(clientInfo) is not { } grantProcessor)
            return NotConfiguredForDelivery();

        switch (updatedRequest)
        {
            case { Status: BackChannelAuthenticationStatus.Authenticated } authenticated:
                return await _redeemer.RedeemAsync(
                    authenticationRequestId, authenticated, clientInfo, grantProcessor);

            case { Status: BackChannelAuthenticationStatus.Denied }:
                return new OidcError(
                    ErrorCodes.AccessDenied,
                    "The authorization request was denied.");

            case null:
                return new OidcError(
                    ErrorCodes.ExpiredToken,
                    "The authentication request has expired");

            default:
                return new OidcError(
                    ErrorCodes.AuthorizationPending,
                    "The authorization request is still pending. " +
                    "The polling interval must be increased by at least 5 seconds for all subsequent requests.");
        }
    }

    /// <summary>
    /// Resolves the processor for the client's registered delivery mode, or null when there is none to
    /// resolve.
    /// </summary>
    /// <remarks>
    /// Both ways of having no processor are one answer, and neither is an exception. The mode is optional
    /// client metadata with nothing tying it to the grant types the client is allowed, so a client can be
    /// registered for this grant carrying no mode at all; and a mode that names no registered processor is
    /// a client configured for a delivery this deployment does not offer. GetRequiredKeyedService answers
    /// both with an InvalidOperationException, which reaches the token endpoint as an unhandled failure -
    /// while the backchannel authentication endpoint answers the identical client state with a named error
    /// an operator can read (BackChannelAuthentication/Validation/ClientValidator.cs).
    /// Keyed lookup with a null check is the dispatch convention this project documents for a value read
    /// off a wire or off client metadata, precisely so an unknown discriminator is a rejection rather than
    /// a throw.
    /// </remarks>
    private IBackChannelGrantProcessor? ResolveProcessor(ClientInfo clientInfo)
        => clientInfo.BackChannelTokenDeliveryMode is { Length: > 0 } deliveryMode
            ? serviceProvider.GetKeyedService<IBackChannelGrantProcessor>(deliveryMode)
            : null;

    /// <summary>
    /// The refusal for a client whose backchannel token delivery mode is missing or unsupported, worded as
    /// its sibling on the backchannel authentication endpoint words it.
    /// </summary>
    private static OidcError NotConfiguredForDelivery()
        => new(
            ErrorCodes.InvalidClient,
            "The client is not properly configured for backchannel authentication. " +
            "A token delivery mode (poll, ping, or push) must be specified.");
}
