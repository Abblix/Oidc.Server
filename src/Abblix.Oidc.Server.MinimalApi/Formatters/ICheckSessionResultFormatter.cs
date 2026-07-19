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

using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats a check-session response (the session-management iframe document) into an <see cref="IResult"/>.
/// </summary>
public interface ICheckSessionResultFormatter
{
    /// <summary>
    /// Formats the check-session response.
    /// </summary>
    /// <param name="response">The check-session response carrying the HTML template.</param>
    /// <returns>An <see cref="IResult"/> that writes the iframe document with a per-request CSP nonce.</returns>
    Task<IResult> FormatResponseAsync(CheckSessionResponse response);
}
