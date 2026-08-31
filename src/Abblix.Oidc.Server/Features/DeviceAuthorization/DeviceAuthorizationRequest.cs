// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Represents a stored device authorization request as defined in RFC 8628.
/// This record is used to persist the state of a device authorization flow
/// between the initial request and when the user completes authentication.
/// </summary>
/// <param name="ClientId">The client identifier that initiated the device authorization request.</param>
/// <param name="Scope">The requested scopes for the authorization.</param>
/// <param name="Resources">The requested resources (RFC 8707) for the authorization.</param>
/// <param name="UserCode">The user-friendly code displayed to the user for verification.</param>
public record DeviceAuthorizationRequest(
    string ClientId,
    string[] Scope,
    Uri[]? Resources,
    string UserCode)
{
    /// <summary>
    /// Specifies the next time the client should poll for updates regarding the authorization request.
    /// This helps manage the timing of polling requests and enforces rate limiting.
    /// </summary>
    public DateTimeOffset? NextPollAt { get; set; }

    /// <summary>
    /// The absolute time when this device authorization request expires (RFC 8628 Section 3.2 fixed lifetime).
    /// Seeded by the storage on <c>StoreAsync</c> and used to cap the refreshed cache TTL at the remaining
    /// lifetime, so regular polling cannot extend the code.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// Whether the fixed lifetime still has time left at <paramref name="now"/>, handing back how much.
    /// </summary>
    /// <remarks>
    /// The comparison sits here because it was being written out at each caller, and one of them
    /// forgot it: user code verification, the step the end user reaches first, decided on
    /// <see cref="Status"/> alone and answered a full result for a record the approval would then refuse.
    /// <para>
    /// It is NOT yet the only place. <c>DeviceCodeGrantHandler</c> still writes both halves out - the
    /// verdict as <c>now &gt;= ExpiresAt</c> and the remaining time as <c>ExpiresAt - now</c> - and that
    /// file is outside this change. The two agree today, and nothing holds them to it: changing the
    /// boundary here to <c>&gt;=</c> is caught by no test anywhere, so a maintainer who reads this as the
    /// single place can split the token endpoint's verdict from the verification endpoint's in silence.
    /// </para>
    /// <para>
    /// It hands back the remaining time because the callers that act on the record need it: a decision
    /// is written with that as the cache TTL, so the code cannot be extended by being decided on.
    /// </para>
    /// </remarks>
    /// <param name="now">The instant to judge against, from the caller's own time provider.</param>
    /// <param name="remaining">How much lifetime is left; zero or negative when there is none.</param>
    /// <returns><c>true</c> while the request can still be acted on.</returns>
    public bool HasLifetimeLeft(DateTimeOffset now, out TimeSpan remaining)
    {
        remaining = ExpiresAt - now;
        return remaining > TimeSpan.Zero;
    }

    /// <summary>
    /// Indicates the current status of the device authorization request.
    /// Defaults to Pending, reflecting that the user has not yet completed authentication.
    /// </summary>
    public DeviceAuthorizationStatus Status { get; set; } = DeviceAuthorizationStatus.Pending;

    /// <summary>
    /// The authorized grant containing the user's authentication session and authorization context.
    /// This is set when the user successfully authorizes the device.
    /// </summary>
    public AuthorizedGrant? AuthorizedGrant { get; set; }

    /// <summary>
    /// RFC 9396 Section 3 Rich Authorization Requests array carried from the original
    /// <c>/device_authorization</c> request. The host's user-verification step reads this
    /// (via <see cref="ValidUserCode"/>) to render structured consent, then threads it into
    /// the <see cref="AuthorizedGrant"/>'s <c>AuthorizationContext</c> when approving;
    /// the eventual access token issued via the device-code grant emits the claim byte-exact.
    /// </summary>
    public JsonArray? AuthorizationDetails { get; set; }
}
