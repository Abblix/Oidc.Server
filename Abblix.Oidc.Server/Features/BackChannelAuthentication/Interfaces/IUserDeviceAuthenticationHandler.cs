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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

/// <summary>
/// Defines the contract for initiating user authentication on a device in the context of a backchannel authentication
/// flow. This interface is responsible for handling the initiation of the authentication process for the end-user
/// on their device, based on a validated backchannel authentication request.
/// </summary>
public interface IUserDeviceAuthenticationHandler
{
    /// <summary>
    /// Initiates the authentication process for the user on their device, based on a validated backchannel
    /// authentication request.
    /// This may involve sending a notification to the user's device, starting an out-of-band
    /// authentication process, or performing other steps required to authenticate the user asynchronously.
    /// </summary>
    /// <param name="request">The validated backchannel authentication request containing user and client information
    /// required to initiate the authentication process.</param>
    /// <returns>
    /// A <see cref="Task"/> representing the asynchronous operation to initiate the authentication process.
    /// </returns>
    Task<Result<AuthSession, RequestError>> InitiateAuthenticationAsync(ValidBackChannelAuthenticationRequest request);
}
