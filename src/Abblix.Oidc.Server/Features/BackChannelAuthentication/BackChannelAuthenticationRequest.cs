// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

/// <summary>
/// Represents a backchannel authentication request as part of the Client-Initiated Backchannel Authentication (CIBA)
/// protocol.
/// This request facilitates the authentication of users without requiring immediate interaction with their devices,
/// allowing for a more flexible and user-friendly authentication experience.
/// </summary>
/// <param name="AuthorizedGrant">
/// The authorized grant associated with this authentication request,
/// containing details about the user's authorization context.
/// </param>
/// <param name="ExpiresAt">
/// The absolute time when this backchannel authentication request expires.
/// </param>
public record BackChannelAuthenticationRequest(AuthorizedGrant AuthorizedGrant, DateTimeOffset ExpiresAt)
{
    /// <summary>
    /// Indicates the current status of the backchannel authentication request.
    /// Defaults to Pending, reflecting that the request has not yet been resolved.
    /// </summary>
    public BackChannelAuthenticationStatus Status { get; set; } = BackChannelAuthenticationStatus.Pending;

    /// <summary>
    /// The client notification endpoint for ping mode.
    /// Populated from client configuration when ping mode is used.
    /// </summary>
    public Uri? ClientNotificationEndpoint { get; set; }

    /// <summary>
    /// The client notification token for ping mode.
    /// Provided by the client in the authentication request for secure notification delivery.
    /// </summary>
    public string? ClientNotificationToken { get; set; }

    /// <summary>
    /// The end users the request will accept, spelled as the requesting client sees them, or <c>null</c>
    /// when it named nobody in particular. An empty array accepts nobody.
    /// </summary>
    /// <remarks>
    /// Recorded here rather than compared once and discarded, because in a decoupled flow the end user
    /// authenticates long after the request was made: the session that answers it arrives through
    /// <see cref="Interfaces.IAuthenticationCompletionHandler.CompleteAsync"/>, and OpenID Connect Core 1.0
    /// Section 3.1.2.2 forbids answering for anyone else. Without this the comparison would have nothing left
    /// to compare against by the time there is a session to judge.
    /// <para>
    /// A set rather than a name, because the two parameters that can name an end user do not agree on the
    /// shape: an <c>id_token_hint</c> names one, and a <c>claims</c> request may list several it would
    /// accept. Section 3.1.2.2 puts both under a single requirement, so both land here.
    /// </para>
    /// </remarks>
    public string[]? RequestedSubjects { get; set; }

    /// <summary>
    /// The RFC 9396 <c>authorization_details</c> the client asked for, as the request-time validators
    /// left them. EMPTY when the request carried none; <c>null</c> only on a request stored before this
    /// field existed, which is why the two are not the same answer.
    /// </summary>
    /// <remarks>
    /// Kept apart from the array on <see cref="BackChannelAuthenticationRequest.AuthorizedGrant"/>, which is
    /// what will be issued. The two are the same until the end user answers: a host whose device UI let them
    /// approve part of the request replaces the grant's context before completing, and this is what that
    /// answer is judged against.
    /// <para>
    /// Recorded rather than derived, for the reason <see cref="RequestedSubjects"/> is: in a decoupled flow
    /// the answer arrives long after the request, through
    /// <see cref="Interfaces.IAuthenticationCompletionHandler.CompleteAsync"/>, and by then the only copy of
    /// what was asked for would be the one the host has just overwritten.
    /// </para>
    /// </remarks>
    public JsonArray? RequestedAuthorizationDetails { get; set; }

    /// <summary>
    /// The authentication levels an essential <c>acr</c> in the request's <c>claims</c> parameter requires
    /// of the ID token. EMPTY when it requires none; <c>null</c> when its requirement is to be read from the
    /// grant's <c>claims</c> instead - on a request stored by a build that did not record the levels, whose
    /// completion then records what it read there, and on one whose qualifiers no level could satisfy, which
    /// the request validator refuses before anything is stored.
    /// </summary>
    /// <remarks>
    /// Recorded rather than derived, for the reason <see cref="RequestedAuthorizationDetails"/> is: a host
    /// expressing partial consent replaces the grant's context, and a context it builds afresh carries no
    /// <c>claims</c> at all, so by the time the level can be judged the grant may no longer say what was
    /// required.
    /// </remarks>
    public string[]? RequiredAuthContextClassRefs { get; set; }
}
