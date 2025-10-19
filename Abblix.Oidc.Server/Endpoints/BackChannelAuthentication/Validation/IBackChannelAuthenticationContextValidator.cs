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

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Defines a contract for validating the context of a backchannel authentication request.
/// Implementations of this interface are responsible for ensuring that the backchannel authentication request
/// meets all necessary validation criteria based on the context, which may include client information,
/// requested scopes, and other parameters.
/// </summary>
public interface IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Asynchronously validates the backchannel authentication request context.
    /// This method checks the context of the request, including client information and requested parameters,
    /// to ensure compliance with security and protocol requirements.
    /// </summary>
    /// <param name="context">The context of the backchannel authentication request that needs to be validated.</param>
    /// <returns>
    /// A task that represents the asynchronous validation operation. The task result contains
    /// a <see cref="RequestError"/> if validation fails, or null if the context is valid.
    /// </returns>
    Task<RequestError?> ValidateAsync(BackChannelAuthenticationValidationContext context);
}
