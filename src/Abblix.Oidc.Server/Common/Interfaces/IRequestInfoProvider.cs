// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;

namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Provides information about the current request, including URIs and security details.
/// </summary>
public interface IRequestInfoProvider
{
    /// <summary>
    /// The base URI of the application.
    /// </summary>
    string ApplicationUri { get; }

    /// <summary>
    /// The request URI.
    /// </summary>
    string RequestUri { get; }

    /// <summary>
    /// The HTTP method of the current request (e.g. <c>GET</c>, <c>POST</c>) in upper case
    /// per RFC 9110 §9. Surfaced for protocol-binding checks (e.g. RFC 9449 §4.3 DPoP
    /// <c>htm</c>) that match the inbound method byte-exact rather than assuming a fixed
    /// value per endpoint.
    /// </summary>
    string RequestMethod { get; }

    /// <summary>
    /// Indicates whether the request is using HTTPS.
    /// </summary>
    bool IsHttps { get; }

    /// <summary>
    /// The base path of the request.
    /// </summary>
    string PathBase { get; }

    /// <summary>
    /// The client's IP address from the current request.
    /// May be null if the IP address cannot be determined.
    /// </summary>
    IPAddress? RemoteIpAddress { get; }
}
