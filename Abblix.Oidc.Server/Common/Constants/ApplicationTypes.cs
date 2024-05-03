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

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Defines constants for different types of applications in OAuth 2.0 and OpenID Connect contexts.
/// </summary>
public static class ApplicationTypes
{
    /// <summary>
    /// Represents a native application type.
    /// This type is typically used for applications installed on a device, such as mobile apps or desktop applications.
    /// </summary>
    public const string Native = "native";

    /// <summary>
    /// Represents a web application type.
    /// This type is used for applications that are accessed through a web browser and typically hosted on a web server.
    /// </summary>
    public const string Web = "web";
}
