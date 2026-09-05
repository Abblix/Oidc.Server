// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
