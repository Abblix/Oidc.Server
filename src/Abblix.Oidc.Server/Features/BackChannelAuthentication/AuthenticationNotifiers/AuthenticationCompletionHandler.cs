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
public abstract partial class AuthenticationCompletionHandler(
    ILogger<AuthenticationCompletionHandler> logger,
    IBackChannelRequestStorage storage,
    ISubjectTypeConverter subjectTypeConverter)
{
    /// <summary>
    /// Completes the authentication process by marking the request as authenticated and delegating
    /// to the mode-specific delivery implementation.
    /// </summary>
    /// <param name="authenticationRequestId">The auth_req_id identifying the authentication request.</param>
    /// <param name="request">The authentication request to mark as authenticated.</param>
    /// <param name="clientInfo">Client information including delivery mode configuration.</param>
    /// <param name="expiresIn">How long the authenticated request remains valid.</param>
    /// <returns>A task representing the asynchronous authentication completion operation.</returns>
    /// <remarks>
    /// This method:
    /// <list type="number">
    ///   <item>Sets the request status to Authenticated</item>
    ///   <item>Delegates to HandleDeliveryAsync for mode-specific token delivery (poll/ping/push)</item>
    /// </list>
    /// Called by AuthenticationCompletionRouter after determining the appropriate delivery mode handler.
    /// </remarks>
    public async Task CompleteAuthenticationAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        ClientInfo clientInfo,
        TimeSpan expiresIn)
    {
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
        // part of the request replaces the grant's context before completing, and RFC 9396 §7 then has
        // the server return what was GRANTED rather than what was asked for.
        //
        // Narrowing is the host's to make; widening is not. The types are compared against what the
        // client actually sent, kept on the stored request precisely because the grant's own copy is the
        // one the host has just overwritten.
        if (EscapedAuthorizationDetailTypes(request) is { Length: > 0 } escaped)
        {
            LogGrantedAuthorizationDetailsExceedTheRequest(
                authenticationRequestId, clientInfo.ClientId, string.Join(", ", escaped));

            await RefuseAsync(authenticationRequestId, request, expiresIn);
            return;
        }

        // Update status to Authenticated before handling delivery
        request.Status = BackChannelAuthenticationStatus.Authenticated;

        await HandleDeliveryAsync(authenticationRequestId, request, clientInfo, expiresIn);
    }

    /// <summary>
    /// The <c>authorization_details</c> types the grant carries and the request never asked for, empty when
    /// the grant stays inside what was requested.
    /// </summary>
    /// <remarks>
    /// Types only. RFC 9396 defines no universal comparator for "is this entry a narrowing of that one", so
    /// what can be judged without knowing a type's schema is whether an entry of that type was asked for at
    /// all. An entry that cannot be read as a JSON object counts as escaped: the conversion drops it silently,
    /// and "nothing escaped" would then be a statement about what could be read rather than about the grant.
    /// </remarks>
    private static string[] EscapedAuthorizationDetailTypes(BackChannelAuthenticationRequest request)
    {
        if (request.AuthorizedGrant.Context.AuthorizationDetails is not { Count: > 0 } granted)
            return [];

        if (granted.ToTypedArray() is not { } typed || typed.Length != granted.Count)
            return ["an entry that is not a JSON object"];

        var requestedTypes = (request.RequestedAuthorizationDetails?.ToTypedArray() ?? [])
            .Select(detail => detail.Type)
            .OfType<string>()
            .ToHashSet(StringComparer.Ordinal);

        return typed
            .Select(detail => detail.Type ?? "(no type)")
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
        await storage.UpdateAsync(authenticationRequestId, request, expiresIn);
    }
}
