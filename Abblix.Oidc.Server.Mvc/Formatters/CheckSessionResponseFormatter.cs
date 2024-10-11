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

using System.Net.Mime;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Provides a response formatter for Check Session frames.
/// </summary>
public class CheckSessionResponseFormatter : ICheckSessionResponseFormatter
{
    /// <summary>
    /// Formats a response for a Check Session frame asynchronously.
    /// </summary>
    /// <param name="response">The Check Session response containing HTML content.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation,
    /// with the formatted response as an <see cref="ActionResult"/>.</returns>
    public Task<ActionResult> FormatResponseAsync(CheckSessionResponse response)
    {
        var result = new ContentResult
        {
            StatusCode = StatusCodes.Status200OK,
            ContentType = MediaTypeNames.Text.Html,
            Content = response.HtmlContent,
        };

        return Task.FromResult<ActionResult>(result);
    }
}
