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
/// Resolves a CIBA request by enriching the raw incoming model with parameters obtained from
/// out-of-band sources, most notably a signed JWT Request Object. The validation pipeline runs
/// against the resolved request, not the raw one.
/// </summary>
public interface IBackChannelAuthenticationRequestFetcher
{
    /// <summary>
    /// Resolves the effective <see cref="BackChannelAuthenticationRequest"/>, merging in parameters from
    /// any external source the implementation knows how to read.
    /// </summary>
    /// <param name="request">The raw backchannel authentication request as parsed from the wire.</param>
    /// <returns>The resolved request on success, or an <see cref="OidcError"/> describing why fetching
    /// or signature/structure validation of the external source failed.</returns>
    Task<Result<BackChannelAuthenticationRequest, OidcError>> FetchAsync(BackChannelAuthenticationRequest request);
}
