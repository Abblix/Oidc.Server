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
