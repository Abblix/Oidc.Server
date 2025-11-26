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

namespace Abblix.Oidc.Server.Features.DeviceAuthorization;

/// <summary>
/// Represents the various states of a device authorization request as defined in RFC 8628.
/// This enumeration defines the possible statuses that a device authorization request can have,
/// facilitating the management of the device authorization flow.
/// </summary>
public enum DeviceAuthorizationStatus
{
    /// <summary>
    /// Indicates that the authorization request is pending and the user has not yet completed authentication.
    /// The client should continue polling the token endpoint.
    /// </summary>
    Pending,

    /// <summary>
    /// Indicates that the user has denied the authorization request.
    /// The client will receive an access_denied error when polling.
    /// </summary>
    Denied,

    /// <summary>
    /// Indicates that the user has successfully authorized the device.
    /// The client will receive tokens when polling the token endpoint.
    /// </summary>
    Authorized,
}
