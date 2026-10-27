// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ResourceIndicators;

/// <summary>
/// Why a request is refused for the resources it is for.
/// </summary>
public static class ResourceRefusals
{
    /// <summary>
    /// The access token would name several resources, while the client's access tokens each name one
    /// (<see cref="ClientInformation.ClientInfo.SingleResourceAccessTokens"/>).
    /// </summary>
    public const string OnePerAccessToken =
        "Each access token of this client is for one resource, so the request has to name the one it is for";
}
