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
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Validation;

/// <summary>
/// Settles the resources (RFC 8707) a device authorization request is for: the ones it names, else the one its scopes
/// refer to where the tenant infers it. Each has to be registered at the tenant and one the client may get an access
/// token for. The token request polling for it spends the request, so the tenant's default resource when nothing names
/// one, and one resource for a client held to one per token, are held here too.
/// </summary>
/// <param name="resourceManager">The service for managing and validating resources.</param>
public class ResourceValidator(IResourceManager resourceManager)
    : IDeviceAuthorizationContextValidator
{
    /// <inheritdoc />
    public Task<OidcError?> ValidateAsync(TenantDefinition tenant, DeviceAuthorizationValidationContext context)
        => Task.FromResult(Validate(tenant, context));

    private OidcError? Validate(TenantDefinition tenant, DeviceAuthorizationValidationContext context)
    {
        var request = context.Request;
        var requested = request.Resources;
        var scope = context.ClientInfo.ScopeServedFor(request.Scope ?? []) ?? [];

        if (requested is not { Length: > 0 })
        {
            if (!ResourceInference.TryInfer(tenant, scope, out var inferred, out var ambiguity))
                return new OidcError(ErrorCodes.InvalidScope, ambiguity);

            if (inferred is null)
                return Refused(context.ClientInfo, tenant, []);

            requested = [inferred];
        }

        if (!resourceManager.Validate(tenant, 
                requested,
                scope,
                out var resources,
                out var errorDescription))
        {
            return new OidcError(ErrorCodes.InvalidTarget, errorDescription);
        }

        if (Refused(context.ClientInfo, tenant, resources) is { } refusal)
            return refusal;

        context.Resources = resources;
        return null;
    }

    /// <summary>
    /// The refusal of the client's rules about <paramref name="resources"/>, or null. The token request polling for
    /// this request spends it, so the resources its access token is addressed to are settled here.
    /// </summary>
    private static OidcError? Refused(ClientInfo client, TenantDefinition tenant, ResourceDefinition[] resources)
        => ResourceRefusals.Of(client, tenant, resources, finalForItsToken: true) is { } refusal
            ? new OidcError(ErrorCodes.InvalidTarget, refusal)
            : null;
}
