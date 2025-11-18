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

using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Provides detailed information about the current HTTP request in an ASP.NET Core application.
/// Implements <see cref="IRequestInfoProvider"/> to encapsulate the retrieval of request-specific data,
/// such as URLs and HTTPS status, facilitating access to these details throughout the application.
/// </summary>
/// <param name="httpContextAccessor">Accessor to obtain the <see cref="HttpContext"/>.</param>
public class HttpRequestInfoAdapter(IHttpContextAccessor httpContextAccessor) : IRequestInfoProvider
{
    /// <summary>
    /// Gets the <see cref="HttpRequest"/> representing the current HTTP request.
    /// </summary>
    private HttpRequest Request
    {
        get
        {
            var httpContext = httpContextAccessor.HttpContext;
            return httpContext.NotNull(nameof(httpContext)).Request;
        }
    }

    /// <summary>
    /// The URI of the current request.
    /// </summary>
    public string RequestUri => Request.GetBaseUrl();

    /// <summary>
    /// The base URI of the application.
    /// </summary>
    public string ApplicationUri => Request.GetAppUrl();

    /// <summary>
    /// Indicates whether the current request is using HTTPS.
    /// </summary>
    public bool IsHttps => Request.IsHttps;

    /// <summary>
    /// The base path of the request.
    /// </summary>
    public string PathBase => Request.PathBase;
}
