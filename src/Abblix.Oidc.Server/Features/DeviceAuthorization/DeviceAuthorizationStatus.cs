// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
