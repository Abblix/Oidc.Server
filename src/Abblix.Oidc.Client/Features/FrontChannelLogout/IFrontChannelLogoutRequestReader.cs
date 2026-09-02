// Abblix OIDC Client Library
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


namespace Abblix.Oidc.Client.Features.FrontChannelLogout;

/// <summary>
/// Reads what a front-channel logout request says (OpenID Connect Front-Channel Logout 1.0 section 2).
/// </summary>
public interface IFrontChannelLogoutRequestReader
{
    /// <summary>
    /// Reads the request's parameters and returns what it is about.
    /// </summary>
    /// <param name="parameters">The query parameters the request carried.</param>
    /// <param name="cancellationToken">Cancels the metadata read this may need.</param>
    /// <returns>What the request says has ended.</returns>
    /// <exception cref="FrontChannelLogoutException">
    /// The request is not one this client will act on.
    /// </exception>
    Task<FrontChannelLogoutNotification> ReadAsync(
        IReadOnlyDictionary<string, string?> parameters, CancellationToken cancellationToken = default);
}
