// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
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
/// <param name="logger">Records a refusal the client is deliberately told nothing specific about.</param>
/// <param name="authorizationDetailsPolicy">Asks the per-type validators whether the grant's
/// authorization_details are still acceptable, which is the only comparison that can see inside an
/// entry.</param>
/// <param name="serviceProvider">Service provider for resolving mode-specific grant processors.</param>
/// <param name="statusNotifier">Notifier for long-polling status changes (null if long-polling disabled).</param>
/// <param name="subjectTypeConverter">
/// Seals the authenticated session's subject the way the requesting client sees it, so it can be compared
/// against the end user the original request named.
/// </param>
public partial class BackChannelAuthenticationGrantHandler(
    ILogger<BackChannelAuthenticationGrantHandler> logger,
    IBackChannelRequestStorage storage,
    IPollScheduleStore pollSchedule,
    IEntityStorageKeyFactory keyFactory,
    IAuthorizationDetailsPolicy authorizationDetailsPolicy,
    TimeProvider timeProvider,
    IOptions<OidcOptions> options,
    IServiceProvider serviceProvider,
    ISubjectTypeConverter subjectTypeConverter,
    IBackChannelLongPollingService? statusNotifier = null) : IAuthorizationGrantHandler
{
    /// <summary>
    /// Whether this grant belongs to the end user the request named, or the request named nobody.
    /// </summary>
    /// <remarks>
    /// The name is taken from the request as it was read, since it is written once when the request is
    /// created and a host has no reason to touch it. What a host does replace is the session, which is what
    /// each caller passes in.
    /// </remarks>
    private bool NamesTheRequestedEndUser(
        string[]? requestedSubjects, AuthorizedGrant grant, ClientInfo clientInfo)
        => requestedSubjects is not { } accepted ||
           subjectTypeConverter.Names(grant.AuthSession, accepted, clientInfo);

    /// <summary>
    /// Redeems an authenticated request, refusing it when the end user who authenticated is not one it
    /// named.
    /// </summary>
    /// <remarks>
    /// OpenID Connect Core 1.0 Section 3.1.2.2: the server "MUST NOT reply with an ID Token or Access Token
    /// for a different user, even if they have an active session with the Authorization Server". In a
    /// decoupled flow the end user authenticates out of band, so what the request named is compared against
    /// whoever the host reported by the time a grant is asked for.
    /// <para>
    /// Judged twice, on two different objects, because one comparison cannot do both jobs. Before the
    /// request is consumed, so an ordinary mismatch spends nothing - redeeming removes the stored entry.
    /// And again on the grant the processor returned, because the processor consumes the stored request
    /// itself, and between the earlier read and that removal a host - writing to that same storage through
    /// the public seam - can replace what is stored. Judging only the earlier copy would approve one grant and hand over another.
    /// </para>
    /// </remarks>
    private async Task<Result<AuthorizedGrant, OidcError>> RedeemAsync(
        string authenticationRequestId,
        StoredRequest request,
        ClientInfo clientInfo,
        IBackChannelGrantProcessor processor,
        CancellationToken cancellationToken)
    {
        // Refused before the request is consumed, so an ordinary mismatch costs the client nothing it could
        // have used: redeeming removes the entry, and a request answerable only for the wrong end user is
        // worth keeping just long enough to say so again if the client polls twice.
        if (!NamesTheRequestedEndUser(request.RequestedSubjects, request.AuthorizedGrant, clientInfo))
            return NotTheRequestedEndUser();

        if (WidensTheRequest(request, request.AuthorizedGrant))
            return NotWhatTheRequestAskedFor();

        // Whom the request named, read before the processor is handed the request. The comparison below
        // exists because what is stored can change between the two checks; taking its yardstick from the
        // same object the processor holds would let one change move both sides together.
        string[]? namedEndUsers = request.RequestedSubjects is { } named ? [..named] : null;

        var result = await processor.ProcessAuthenticatedRequestAsync(authenticationRequestId, request);
        if (result.TryGetFailure(out var error))
            return error;

        var grant = result.GetSuccess();

        // Judged again, on what was actually consumed. The processor removes the stored entry and returns
        // the grant it found there, so between the check above and that removal a host - writing to that
        // same storage through the public seam - can replace what is stored, which is the ordinary shape
        // of a retried or corrected completion rather than an attack. Approving one grant and handing over
        // another is the whole failure this comparison exists to prevent.
        if (!NamesTheRequestedEndUser(namedEndUsers, grant, clientInfo))
            return NotTheRequestedEndUser();

        // And the same for what the grant authorises. The completion path judges this too, but a host can
        // complete with a narrowed grant and then store a wider one before the client polls - the same
        // window the subject comparison above exists for, and the same answer.
        if (WidensTheRequest(request, grant))
            return NotWhatTheRequestAskedFor();

        // And what the type comparison structurally cannot see: an entry of a type the request DID ask
        // for, carrying content it did not. RFC 9396 section 6.1 leaves that to the type's own validator, so this
        // asks it - on a copy, because the question must not rewrite its own subject.
        if (await authorizationDetailsPolicy.RefuseAsync(grant, clientInfo, cancellationToken)
            is not { } refusal)
            return grant;

        // The reason goes to the log and a fixed string to the client: a granted-phase rejection names
        // a host-side defect, and its text is written for whoever has to fix it.
        LogGrantedAuthorizationDetailsRefused(clientInfo.ClientId, refusal.Reason);
        return refusal.Error;
    }

    private static OidcError NotTheRequestedEndUser()
        => new(ErrorCodes.AccessDenied, "The authenticated end user is not the one the request named");

    private static OidcError NotWhatTheRequestAskedFor()
        => new(ErrorCodes.AccessDenied,
            "The grant carries authorization_details the authentication request did not ask for");

    /// <summary>
    /// Whether the grant carries an <c>authorization_details</c> type the request never asked for.
    /// </summary>
    /// <remarks>
    /// Types only, for the reason the completion path gives: RFC 9396 section 6.1 defines no universal
    /// comparator for
    /// intra-entry narrowing. A null baseline means the request predates the field rather than asked for
    /// nothing, and is left alone, since refusing it would deny an authentication the end user approved
    /// before the upgrade.
    /// </remarks>
    private static bool WidensTheRequest(StoredRequest request, AuthorizedGrant grant)
    {
        if (grant.Context.AuthorizationDetails is not { Count: > 0 } granted ||
            request.RequestedAuthorizationDetails is not { } requested)
            return false;

        if (granted.ToTypedArray() is not { } typed || typed.Length != granted.Count)
            return true;

        var requestedTypes = AuthorizationDetailTypes.NamedBy(requested);

        return !typed.All(detail => detail.Type is { } type && requestedTypes.Contains(type));
    }

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
            // If the request is not found or has expired, return an error indicating token expiration
            null => new OidcError(ErrorCodes.ExpiredToken, "The authentication request has expired"),

            // If the client making the request is not the same as the one that initiated the authentication
            // This validation MUST occur before any status-specific processing for security
            { AuthorizedGrant.Context.ClientId: var clientId } when clientId != clientInfo.ClientId
                => new OidcError(ErrorCodes.InvalidGrant, "The authentication request was issued to another client"),

            // If the user has been authenticated, process mode-specific token retrieval
            { Status: BackChannelAuthenticationStatus.Authenticated } authenticated
                => await RedeemAsync(
                    request.AuthenticationRequestId, authenticated, clientInfo, processor, cancellationToken),

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
                advanced, authenticationRequestId, clientInfo, cancellationToken);
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
            updatedRequest, authenticationRequestId, clientInfo, cancellationToken);
    }

    /// <summary>
    /// Processes the updated authentication request after status change notification.
    /// Handles Authenticated, Denied, and Expired states appropriately.
    /// </summary>
    /// <param name="updatedRequest">The updated authentication request from storage, or null if expired.</param>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="clientInfo">Client information for determining token delivery mode.</param>
    /// <param name="cancellationToken">Forwarded to the per-type validators that judge the grant's
    /// authorization_details before it is handed over.</param>
    /// <returns>Either an authorized grant, access denied error, expired token error, or authorization_pending.</returns>
    private async Task<Result<AuthorizedGrant, OidcError>> ProcessUpdatedRequest(
        Features.BackChannelAuthentication.BackChannelAuthenticationRequest? updatedRequest,
        string authenticationRequestId,
        ClientInfo clientInfo,
        CancellationToken cancellationToken)
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
                return await RedeemAsync(
                    authenticationRequestId, authenticated, clientInfo, grantProcessor, cancellationToken);

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
