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

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;

/// <summary>
/// Endpoint contract for the OpenID Connect CIBA (Client-Initiated Backchannel Authentication) flow,
/// orchestrating fetch, validation and processing of an incoming backchannel authentication request
/// to produce the response defined in CIBA Core 1.0 §7.
/// </summary>
public interface IBackChannelAuthenticationHandler
{
    /// <summary>
    /// Processes a backchannel authentication request and returns either a successful response
    /// (containing <c>auth_req_id</c>, <c>expires_in</c> and the polling <c>interval</c>) or an
    /// <see cref="OidcError"/> describing why the request was rejected.
    /// </summary>
    /// <param name="request">The incoming CIBA authentication request, after parsing of standard parameters.</param>
    /// <param name="clientRequest">Transport-level information about the client invocation
    /// (e.g. authentication credentials, headers) used to identify and authorize the calling client.</param>
    /// <returns>A <see cref="Result{TSuccess,TFailure}"/> wrapping a
    /// <see cref="BackChannelAuthenticationSuccess"/> or an <see cref="OidcError"/>.</returns>
    Task<Result<BackChannelAuthenticationSuccess, OidcError>> HandleAsync(
        BackChannelAuthenticationRequest request,
        ClientRequest clientRequest);
}
