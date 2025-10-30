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
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.RequestFetching;

/// <summary>
/// Defines a contract for fetching and validating backchannel authentication requests in the context of
/// CIBA (Client-Initiated Backchannel Authentication) flows.
/// </summary>
public interface IBackChannelAuthenticationRequestFetcher
{
    /// <summary>
    /// Asynchronously fetches and validates a backchannel authentication request. This method handles the retrieval
    /// and any necessary validation or processing to ensure that the request is ready for further handling.
    /// </summary>
    /// <param name="request">The backchannel authentication request to be fetched and validated.</param>
    /// <returns>A task that returns a <see cref="Result{BackChannelAuthenticationRequest, AuthError}"/>
    /// indicating whether the fetch was successful or if it resulted in an error.</returns>
    Task<Result<BackChannelAuthenticationRequest, AuthError>> FetchAsync(BackChannelAuthenticationRequest request);
}
