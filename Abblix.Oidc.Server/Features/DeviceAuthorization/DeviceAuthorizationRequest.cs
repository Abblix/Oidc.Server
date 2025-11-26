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
    /// Indicates the current status of the device authorization request.
    /// Defaults to Pending, reflecting that the user has not yet completed authentication.
    /// </summary>
    public DeviceAuthorizationStatus Status { get; set; } = DeviceAuthorizationStatus.Pending;

    /// <summary>
    /// The authorized grant containing the user's authentication session and authorization context.
    /// This is set when the user successfully authorizes the device.
    /// </summary>
    public AuthorizedGrant? AuthorizedGrant { get; set; }
}
