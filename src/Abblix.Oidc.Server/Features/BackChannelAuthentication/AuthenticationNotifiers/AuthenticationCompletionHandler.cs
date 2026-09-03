// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Microsoft.Extensions.Logging;

using Abblix.Oidc.Server.Features.RichAuthorizationRequests;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;

/// <summary>
/// Abstract base class for CIBA authentication completion handlers.
/// Provides common functionality for validation, status management, and delivery orchestration.
/// Derived classes implement specific token delivery modes (poll, ping, push) per CIBA specification.
/// </summary>
/// <remarks>
/// Do not add a converter-less constructor overload for the convenience of a derived class: it would
/// compile and silently lose the comparison in <see cref="CompleteAuthenticationAsync"/>, which is what
/// keeps a request from being answered for an end user it did not name.
/// </remarks>
/// <param name="logger">Logger for tracking completion events and errors.</param>
/// <param name="storage">Storage for persisting authentication request state.</param>
/// <param name="subjectTypeConverter">Seals a session's subject the way the requesting client sees it,
/// so the end user who authenticated can be compared against the one the request named.</param>
/// <param name="statusNotifier">Wakes a client waiting on a long poll. Optional, and defaulted so a
/// handler outside this library keeps compiling - a deployment that registered none simply has nobody
/// to wake.</param>
public abstract partial class AuthenticationCompletionHandler(
    ILogger<AuthenticationCompletionHandler> logger,
    IBackChannelRequestStorage storage,
    ISubjectTypeConverter subjectTypeConverter,
    IBackChannelLongPollingService? statusNotifier = null)
{
    /// <summary>
    /// Completes the authentication process by marking the request as authenticated and delegating
    /// to the mode-specific delivery implementation.
    /// </summary>
    /// <param name="authenticationRequestId">The auth_req_id identifying the authentication request.</param>
    /// <param name="request">The authentication request carrying the grant the end user approved. Its
    /// own Status is not read: whether this request may still be answered is decided from the STORED
    /// record, so a caller cannot make the decision by setting a field on its own copy.</param>
    /// <param name="clientInfo">Client information including delivery mode configuration.</param>
    /// <param name="expiresIn">How long the authenticated request remains valid.</param>
    /// <returns>A task representing the asynchronous authentication completion operation.</returns>
    /// <remarks>
    /// This method:
    /// <list type="bullet">
    ///   <item>Refuses unless the STORED record reads Pending</item>
    ///   <item>Refuses an answer from somebody other than the end user the request named, by denying or
    ///   removing according to the mode</item>
    ///   <item>Sets the request status to Authenticated</item>
    ///   <item>Delegates to HandleDeliveryAsync for mode-specific token delivery (poll/ping/push)</item>
    /// </list>
    /// Called by AuthenticationCompletionRouter after determining the appropriate delivery mode handler.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The store does not hold a PENDING record under this
    /// identifier. The full statement of the condition, and why it is stated that way rather than as a
    /// list of causes, is on <see cref="IAuthenticationCompletionHandler.CompleteAsync"/>.</exception>
    public async Task CompleteAuthenticationAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        ClientInfo clientInfo,
        TimeSpan expiresIn)
    {
        // One authentication, one completion. The end user answered once, so a second delivery of that
        // answer is wrong whatever it carries - which is why this refuses rather than replaying the
        // narrowed grant. Replaying would make the second attempt correctly scoped and no less of a
        // second attempt.
        //
        // Read from STORAGE, not from the request the caller handed in. A host is free to set Status on
        // its own copy - some do, and the end-to-end fixture here is one of them - so a guard reading
        // that field would refuse those on their FIRST completion, and would be advisory besides:
        // whether the refusal fires would be the choice of the caller it exists to constrain. The
        // stored record is the one thing this seam owns.
        //
        // Push is what makes a second completion reachable at all. Poll and ping persist Authenticated
        // before they deliver, so a repeat already found a spent record; push stored nothing until
        // PushModeCompletionHandler was given the same write, and until then a failed delivery left a
        // record that still read Pending and still carried what the CLIENT asked for.
        //
        // Stated as what must be TRUE rather than as the ways it can fail. A record that is gone is not
        // a lesser case of one that is spent: a poll can have redeemed and removed it, and completing on
        // top of that mints against a record nobody can check and writes it back into existence.
        //
        // And the refusal says only that, never WHY. Absence has more causes than this seam can tell
        // apart - a poll redeemed it, a push delivered it, its lifetime ran out while the end user was
        // deciding, or push's own refusal path removed it after a configuration fault, where nothing was
        // answered at all. Naming one of them would send an operator who just fixed a client
        // registration looking for a second completion that never happened.
        var stored = await storage.TryGetAsync(authenticationRequestId);
        if (stored is not { Status: BackChannelAuthenticationStatus.Pending })
        {
            LogNotPendingOnCompletion(authenticationRequestId, stored?.Status.ToString());

            throw new InvalidOperationException(
                "The authentication request cannot be completed: the stored record "
                + (stored is null
                    ? "is not there"
                    : $"reads {stored.Status} rather than {BackChannelAuthenticationStatus.Pending}")
                + ". Only a pending request can be answered. Recovering from a failed delivery means "
                + "asking the end user again rather than completing the same request twice.");
        }

        // Whoever answered the device has to be the end user the request named. OpenID Connect Core 1.0
        // Section 3.1.2.2: the server "MUST NOT reply with an ID Token or Access Token for a different user,
        // even if they have an active session with the Authorization Server". The end user authenticated out
        // of band, so this is the first moment there is anybody to judge - and the last before delivery.
        //
        // Judged here rather than in the router so that each mode refuses the way it already refuses its own
        // failures: a mode that cannot leave a denied request behind removes it instead.
        if (request.RequestedSubjects is { } accepted &&
            !subjectTypeConverter.Names(request.AuthorizedGrant.AuthSession, accepted, clientInfo))
        {
            LogAuthenticatedUserNotTheOneRequested(authenticationRequestId, clientInfo.ClientId);
            await RefuseAsync(authenticationRequestId, request, expiresIn);
            return;
        }

        // The end user's answer arrives here and nowhere else, which makes this the seam a narrowed
        // authorization_details set travels through: a host whose device interaction let them approve
        // part of the request replaces the grant's context before completing, and RFC 9396 section 7 then has
        // the server return what was GRANTED rather than what was asked for.
        //
        // Narrowing is the host's to make; widening is not. The types are compared against what the
        // client actually sent, kept on the stored request precisely because the grant's own copy is the
        // one the host has just overwritten.
        //
        // An EMPTY granted set completes rather than refusing, and that differs on purpose from the
        // authorization endpoint, which answers access_denied to a consent decision that granted no
        // entries. There the refusal has somewhere to go: a browser is waiting and the client learns why.
        // Here the only way to say "the user refused" is to deny the whole request, which a host does
        // through its own denial path; turning an empty set into a denial would take that choice away and
        // refuse a host that legitimately issues a token with no authorization_details at all.
        if (EscapedAuthorizationDetailTypes(request) is { Length: > 0 } escaped)
        {
            LogGrantedAuthorizationDetailsExceedTheRequest(
                authenticationRequestId, clientInfo.ClientId, string.Join(", ", escaped));

            await RefuseAsync(authenticationRequestId, request, expiresIn);
            return;
        }

        // What is NOT asked here, and where each mode asks it. The per-type validators judge the
        // CONTENT of an entry whose type was requested, which the comparison above structurally cannot
        // see. Poll and ping meet that question at the token endpoint when the grant is redeemed, and
        // asking it again here would pre-empt that one: the refusal would become a denial, and the
        // client would read access_denied where the redemption gate answers with the code RFC 9396
        // registers for it. Push has no token endpoint to reach, so PushModeCompletionHandler asks it
        // there, before it mints.

        // Update status to Authenticated before handling delivery
        request.Status = BackChannelAuthenticationStatus.Authenticated;

        await HandleDeliveryAsync(authenticationRequestId, request, clientInfo, expiresIn);
    }

    /// <summary>
    /// The <c>authorization_details</c> types the grant carries and the request never asked for, empty when
    /// the grant stays inside what was requested.
    /// </summary>
    /// <remarks>
    /// Types only. RFC 9396 section 6.1 defines no universal comparator for "is this entry a narrowing
    /// of that one", so
    /// what can be judged without knowing a type's schema is whether an entry of that type was asked for at
    /// all. An entry that cannot be read as a JSON object counts as escaped: the conversion drops it silently,
    /// and "nothing escaped" would then be a statement about what could be read rather than about the grant.
    /// </remarks>
    private static string[] EscapedAuthorizationDetailTypes(BackChannelAuthenticationRequest request)
    {
        if (request.AuthorizedGrant.Context.AuthorizationDetails is not { Count: > 0 } granted)
            return [];

        // Null means the request predates this field, not that it asked for nothing: a build that did
        // not record it stored the requested entries on the grant alone. Judging those against an empty
        // baseline would refuse, on the first completion after an upgrade, an authentication the end
        // user has already approved. A request this build stored says "asked for nothing" with an empty
        // array instead.
        if (request.RequestedAuthorizationDetails is not { } requested)
            return [];

        if (granted.ToTypedArray() is not { } typed || typed.Length != granted.Count)
            return ["an entry that is not a JSON object"];

        // Absence is refused on its own rather than compared as a stand-in value, which a client could
        // otherwise request as a real type and thereby admit every entry that has none.
        if (Array.Exists(typed, detail => detail.Type is null))
            return ["an entry carrying no type"];

        var requestedTypes = AuthorizationDetailTypes.NamedBy(requested);

        return typed
            .Select(detail => detail.Type!)
            .Where(type => !requestedTypes.Contains(type))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    /// <summary>
    /// Refuses a request whose authenticated end user is not the one it named.
    /// </summary>
    /// <remarks>
    /// Denying and leaving the request behind is right for a mode whose client polls, since the poll is what
    /// carries the outcome back. A mode that delivers instead of being polled overrides this, because a
    /// denied request its client can never read is an orphan rather than an answer.
    /// </remarks>
    protected virtual Task RefuseAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        TimeSpan expiresIn)
        => DenyRequestAsync(authenticationRequestId, request, expiresIn);

    /// <summary>
    /// Handles the token delivery according to the specific delivery mode (poll, ping, or push).
    /// Derived classes implement the specific delivery logic for their mode.
    /// </summary>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="request">The authenticated request containing the authorized grant.</param>
    /// <param name="clientInfo">Client information including delivery mode configuration.</param>
    /// <param name="expiresIn">How long the authenticated request remains valid.</param>
    protected abstract Task HandleDeliveryAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        ClientInfo clientInfo,
        TimeSpan expiresIn);

    /// <summary>
    /// Validates that the required notification endpoint and bearer token are configured.
    /// Both are mandatory for ping and push modes per CIBA specification.
    /// </summary>
    /// <param name="endpoint">The client notification endpoint.</param>
    /// <param name="token">The client notification token.</param>
    /// <param name="deliveryMode">Name of the mode for logging (e.g., "Push mode", "Ping mode").</param>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <returns>True if both endpoint and token are present; otherwise, false.</returns>
    protected bool ValidateNotificationConfiguration(
        [NotNullWhen(true)] Uri? endpoint,
        [NotNullWhen(true)] string? token,
        string deliveryMode,
        string clientId,
        string authenticationRequestId)
    {
        var hasToken = token != null;
        if (hasToken && endpoint != null)
            return true;

        LogMissingNotificationConfig(
            deliveryMode,
            clientId,
            authenticationRequestId,
            endpoint?.ToString() ?? "null",
            hasToken);

        return false;
    }

    /// <summary>
    /// Marks the authentication request as denied and persists the status to storage.
    /// This is used when configuration errors or token generation failures prevent successful authentication.
    /// </summary>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="request">The authentication request to mark as denied.</param>
    /// <param name="expiresIn">How long the denied status remains in storage for client polling.</param>
    protected async Task DenyRequestAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        TimeSpan expiresIn)
    {
        request.Status = BackChannelAuthenticationStatus.Denied;
        await StoreAsync(authenticationRequestId, request, expiresIn);
    }

    /// <summary>
    /// Writes the request and wakes whoever is waiting on it.
    /// </summary>
    /// <remarks>
    /// One place, so that a handler cannot write a status without waking whoever waits on it. No derived
    /// handler holds an <see cref="IBackChannelRequestStorage"/> of its own any more, which is what makes
    /// this the only write path today - and NOT something the compiler enforces: a field initialised from
    /// a primary-constructor parameter captures nothing, so one line takes that door back. What holds it
    /// shut is <c>NoCompletionHandlerKeepsItsOwnStorage</c> in the unit tests, which reads the TYPES
    /// rather than the call sites and so covers a handler that does not exist yet. The previous shape,
    /// where each handler had its own storage field, is how ping came to signal nothing while its clients
    /// waited and how push kept writing past this method afterwards.
    /// <para>
    /// A transition made by REMOVING the request rather than writing it wakes nobody, deliberately, and
    /// only push makes one from here - through <see cref="TakeRequestAsync"/>, because a denied request
    /// its client can never read is an orphan. Two more removals live outside this class entirely: the
    /// grant handler drops a request whose stored expiry has passed and answers expired_token, and a
    /// redemption drops the request it just answered. Neither passes through here, so a signal added to
    /// this class would not fire for them. A waiter woken by any of the three would read a record that is
    /// gone, which is what its own timeout already handles.
    /// </para>
    /// <para>
    /// Whether anybody IS waiting is not this method's question either. Push goes through it and wakes
    /// nobody, because nothing hands push a notifier: its constructor has no such parameter, so no
    /// container configuration can supply one. A deployment that registered no notifier skips the call.
    /// </para>
    /// </remarks>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="request">The request whose status has just changed.</param>
    /// <param name="expiresIn">How long the stored record remains available.</param>
    protected async Task StoreAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        TimeSpan expiresIn)
    {
        await storage.UpdateAsync(authenticationRequestId, request, expiresIn);

        if (statusNotifier != null)
        {
            await statusNotifier.NotifyStatusChangeAsync(authenticationRequestId, request.Status);
        }
    }

    /// <summary>
    /// Takes the request away, for a mode that answers by removing it rather than by writing a status.
    /// </summary>
    /// <remarks>
    /// Beside <see cref="StoreAsync"/> so that a derived handler needs no storage of its own, which is
    /// what keeps the write path from having a second door. Nobody is woken: a waiter reading a record
    /// that has just gone learns nothing its own timeout does not already tell it.
    /// </remarks>
    /// <param name="authenticationRequestId">The request to take away.</param>
    /// <returns>The request, when this caller took it - which means the protocol ran to the end and this
    /// caller's own claim was still in the store; otherwise null. A null covers the record not being
    /// there, somebody else having taken it, and a claim that expired mid-protocol, which happens to a
    /// single caller with nobody to lose to. A store fault after the removal raises rather than
    /// returning null.</returns>
    protected Task<BackChannelAuthenticationRequest?> TakeRequestAsync(string authenticationRequestId)
        => storage.TryRemoveAsync(authenticationRequestId);
}
