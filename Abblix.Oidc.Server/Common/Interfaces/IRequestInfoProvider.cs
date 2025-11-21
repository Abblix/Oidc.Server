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
