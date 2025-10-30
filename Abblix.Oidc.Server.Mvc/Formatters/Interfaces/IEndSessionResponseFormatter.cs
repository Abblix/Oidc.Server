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
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters.Interfaces;

/// <summary>
/// Defines an interface for formatting a response to an end-session request and response.
/// </summary>
public interface IEndSessionResponseFormatter
{
    /// <summary>
    /// Formats a response asynchronously for an end-session request and response.
    /// </summary>
    /// <param name="request">The end-session request.</param>
    /// <param name="response">The end-session response to be formatted.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation,
    /// with the formatted response as an <see cref="ActionResult"/>.</returns>
    Task<ActionResult> FormatResponseAsync(EndSessionRequest request, Result<EndSessionSuccess, AuthError> response);
}
