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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters.Interfaces;

/// <summary>
/// Defines an interface for formatting client registration responses.
/// </summary>
public interface IRegisterClientResponseFormatter
{
    /// <summary>
    /// Formats the given client registration response asynchronously.
    /// </summary>
    /// <param name="request">The original client registration request.</param>
    /// <param name="response">The client registration response to format.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.
    /// The task result contains the formatted <see cref="ActionResult"/>.</returns>
    Task<ActionResult> FormatResponseAsync(ClientRegistrationRequest request, Result<ClientRegistrationSuccessResponse, AuthError> response);
}
