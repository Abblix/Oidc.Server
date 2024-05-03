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

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Provides an interface for processing client registration requests.
/// </summary>
public interface IRegisterClientRequestProcessor
{
    /// <summary>
    /// Processes the given client registration request asynchronously.
    /// </summary>
    /// <param name="request">The client registration request to process.</param>
    /// <returns>A task representing the asynchronous operation. The task result contains the client registration response.</returns>
    Task<ClientRegistrationResponse> ProcessAsync(ValidClientRegistrationRequest request);
}
