// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

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

    /// <summary>
    /// The access token would be addressed to a resource the client may not get a token for
    /// (<see cref="ClientInformation.ClientInfo.AllowedResources"/>).
    /// </summary>
    public const string NotAllowedForClient = "The client may not get an access token for the resource";

    /// <summary>
    /// Why <paramref name="client"/> is refused a request settling <paramref name="resources"/>, or null.
    /// </summary>
    /// <param name="client">The client making the request.</param>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="resources">The resources the request names or its scopes infer.</param>
    /// <param name="finalForItsToken">Whether no later token request names the resources of the access token
    /// this request leads to, as for an authorization request returning one, a device authorization request or a
    /// backchannel authentication request, so the resources settled here are the ones that token carries.</param>
    /// <remarks>
    /// A resource outside the client's list is refused wherever it is named. The tenant's default resource, which
    /// an access token is addressed to when nothing names one, and more than one resource for a client held to one
    /// per token are refused here only when no token request follows to settle them.
    /// </remarks>
    public static string? Of(
        ClientInfo client,
        TenantDefinition tenant,
        ResourceDefinition[] resources,
        bool finalForItsToken)
    {
        if (resources.Any(resource => !client.MayGetTokenFor(resource.Resource)))
            return NotAllowedForClient;

        if (!finalForItsToken)
            return null;

        if (resources.Length == 0 &&
            tenant.DefaultResourceIndicator is { } defaultResource &&
            !client.MayGetTokenFor(defaultResource))
        {
            return NotAllowedForClient;
        }

        if (client.SingleResourceAccessTokens && resources.Length > 1)
            return OnePerAccessToken;

        return null;
    }
}
