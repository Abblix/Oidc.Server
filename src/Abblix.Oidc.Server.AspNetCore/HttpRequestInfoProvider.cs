// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Supplies the core with information about the current HTTP request, reading it from the ambient
/// <see cref="HttpContext"/>. Touches only ASP.NET Core's HTTP abstractions (no MVC, no Minimal API types), so it is
/// shared by both transport adapters as the default <see cref="IRequestInfoProvider"/>.
/// </summary>
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
