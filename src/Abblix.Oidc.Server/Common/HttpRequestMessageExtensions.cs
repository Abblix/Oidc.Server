// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Extension methods for <see cref="HttpRequestMessage"/>.
/// </summary>
public static class HttpRequestMessageExtensions
{
    /// <summary>
    /// Adds a Bearer token authorization header to the HTTP request.
    /// </summary>
    /// <param name="request">The HTTP request message.</param>
    /// <param name="bearerToken">The bearer token to include in the Authorization header.</param>
    public static void AddBearerToken(this HttpRequestMessage request, string bearerToken)
    {
        request.Headers.Add(HttpRequestHeaders.Authorization, $"{TokenTypes.Bearer} {bearerToken}");
    }
}
