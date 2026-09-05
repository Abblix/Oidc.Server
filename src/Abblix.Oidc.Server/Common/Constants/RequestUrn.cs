// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Provides constants for OAuth request URIs, ensuring they conform to the standardized URN notation.
/// </summary>
public static class RequestUrn
{
    /// <summary>
    /// The prefix for OAuth request URIs as per the Internet Engineering Task Force (IETF) parameters.
    /// </summary>
    public const string Prefix = "urn:ietf:params:oauth:request_uri:";
}
