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

using System.Net;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Supplies the core with information about the current HTTP request, reading it from the ambient
/// <see cref="HttpContext"/>.
/// </summary>
/// <remarks>
/// Equivalent to the MVC integration's <c>HttpRequestInfoAdapter</c>: both read only <see cref="HttpContext"/> and
/// carry no MVC dependency, so the implementation is shared in spirit and a candidate for a common HTTP-neutral
/// package if one is later extracted.
/// </remarks>
public class HttpRequestInfoProvider(IHttpContextAccessor httpContextAccessor) : IRequestInfoProvider
{
    private HttpRequest Request => httpContextAccessor.HttpContext.NotNull(nameof(HttpContext)).Request;

    /// <inheritdoc />
    public string RequestUri => Request.GetBaseUrl();

    /// <inheritdoc />
    public string RequestMethod => Request.Method;

    /// <inheritdoc />
    public string ApplicationUri => Request.GetAppUrl();

    /// <inheritdoc />
    public bool IsHttps => Request.IsHttps;

    /// <inheritdoc />
    public string PathBase => Request.PathBase;

    /// <inheritdoc />
    public IPAddress? RemoteIpAddress => httpContextAccessor.HttpContext?.Connection.RemoteIpAddress;
}
