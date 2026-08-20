// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

/// <summary>
/// Represents the various states of a backchannel authentication request.
/// This enumeration defines the possible statuses that an authentication request can have,
/// facilitating the management of the authentication process in Client-Initiated Backchannel Authentication (CIBA).
/// </summary>
public enum BackChannelAuthenticationStatus
{
    /// <summary>
    /// Indicates that the authentication request is pending and has not yet been processed.
    /// </summary>
    Pending,

    /// <summary>
    /// Indicates that the authentication request has been denied, either by the user or the system.
    /// </summary>
    Denied,

    /// <summary>
    /// Indicates that the authentication request has been successfully authenticated.
    /// </summary>
    Authenticated,
}
