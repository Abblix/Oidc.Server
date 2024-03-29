// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Provides detailed information about the current HTTP request in an ASP.NET Core application.
/// Implements <see cref="IRequestInfoProvider"/> to encapsulate the retrieval of request-specific data,
/// such as URLs and HTTPS status, facilitating access to these details throughout the application.
/// </summary>
public class HttpRequestInfoAdapter : IRequestInfoProvider
{
    /// <summary>
    /// Initializes a new instance of the <see cref="HttpRequestInfoAdapter"/> class.
    /// </summary>
    /// <param name="httpContextAccessor">Accessor to obtain the <see cref="HttpContext"/>.</param>
    public HttpRequestInfoAdapter(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>
    /// Gets the <see cref="HttpRequest"/> representing the current HTTP request.
    /// </summary>
    private HttpRequest Request
    {
        get
        {
            var httpContext = _httpContextAccessor.HttpContext;
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
