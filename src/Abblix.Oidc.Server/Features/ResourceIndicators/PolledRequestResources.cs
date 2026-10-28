// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Features.ResourceIndicators;

/// <summary>
/// Settles the resources of a request whose token is polled for afterwards, a device authorization or a backchannel
/// authentication request: the token request polling for it spends it, so the resources its access token is
/// addressed to are settled, and held to the client's rules, at the request itself.
/// </summary>
internal static class PolledRequestResources
{
    /// <summary>
    /// Settles <paramref name="resources"/>: the ones the request names, else the one its scopes refer to where the
    /// tenant infers it, each registered at the tenant and one the client may get an access token for.
    /// </summary>
    /// <returns>The refusal of the request for its resources, or null once they are settled.</returns>
    public static OidcError? Settle(
        IResourceManager resourceManager,
        TenantDefinition tenant,
        ClientInfo client,
        Uri[]? requested,
        string[] scope,
        out ResourceDefinition[] resources)
    {
        resources = [];
        if (requested is not { Length: > 0 })
        {
            if (!ResourceInference.TryInfer(tenant, scope, out var inferred, out var ambiguity))
                return new OidcError(ErrorCodes.InvalidScope, ambiguity);

            if (inferred is null)
                return Refused(client, tenant, resources);

            requested = [inferred];
        }

        if (!resourceManager.Validate(tenant, requested, scope, out var settled, out var errorDescription))
            return new OidcError(ErrorCodes.InvalidTarget, errorDescription);

        resources = settled;
        return Refused(client, tenant, settled);
    }

    private static OidcError? Refused(ClientInfo client, TenantDefinition tenant, ResourceDefinition[] resources)
        => ResourceRefusals.Of(client, tenant, resources, finalForItsToken: true) is { } refusal
            ? new OidcError(ErrorCodes.InvalidTarget, refusal)
            : null;
}
