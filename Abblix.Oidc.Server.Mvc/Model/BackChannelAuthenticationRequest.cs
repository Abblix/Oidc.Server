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

using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// Represents a back-channel authentication request in the context of OAuth 2.0 or OpenID Connect.
/// This record extends from <see cref="ClientRequest"/> and is used to capture and map the necessary
/// parameters for initiating a back-channel authentication flow.
/// </summary>
public record BackChannelAuthenticationRequest : ClientRequest
{
    /// <summary>
    /// Maps the properties of this back-channel authentication request to a corresponding
    /// <see cref="Core.BackChannelAuthenticationRequest"/> object. This mapping facilitates
    /// the processing of the request in the core layers of the authentication framework.
    /// </summary>
    /// <returns>
    /// A <see cref="Core.BackChannelAuthenticationRequest"/> object populated with the relevant
    /// data from this request.
    /// </returns>
    public new Core.BackChannelAuthenticationRequest Map()
    {
        return new Core.BackChannelAuthenticationRequest
        {
        };
    }
}
