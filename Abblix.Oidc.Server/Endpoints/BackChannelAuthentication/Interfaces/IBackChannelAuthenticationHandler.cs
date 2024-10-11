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

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;

/// <summary>
/// Defines the contract for handling backchannel authentication requests in the context of OpenID Connect.
/// Implementations of this interface are responsible for processing the incoming authorization requests
/// and generating appropriate backchannel authentication responses.
/// </summary>
public interface IBackChannelAuthenticationHandler
{
    /// <summary>
    /// Handles the processing of a backchannel authentication request asynchronously.
    /// The method takes an authorization request as input and returns a corresponding
    /// backchannel authentication response, which could be a success or error response.
    /// </summary>
    /// <param name="request">
    ///     The authorization request containing the details of the backchannel authentication request.</param>
    /// <param name="clientRequest"></param>
    /// <returns>
    /// A task that represents the asynchronous operation, containing the backchannel authentication response.
    /// </returns>
    Task<BackChannelAuthenticationResponse> HandleAsync(BackChannelAuthenticationRequest request,
        ClientRequest clientRequest);
}
