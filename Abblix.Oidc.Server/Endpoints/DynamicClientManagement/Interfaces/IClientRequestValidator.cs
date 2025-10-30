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
using Abblix.Utils;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Represents an interface for validating client requests in the context of OpenID Connect.
/// </summary>
public interface IClientRequestValidator
{
    /// <summary>
    /// Validates a client request asynchronously and returns a result of type Result<ValidClientRequest, AuthError>.
    /// </summary>
    /// <param name="request">The client request to validate.</param>
    /// <returns>A task representing the validation result.</returns>
    Task<Result<ValidClientRequest, AuthError>> ValidateAsync(ClientRequest request);
}
