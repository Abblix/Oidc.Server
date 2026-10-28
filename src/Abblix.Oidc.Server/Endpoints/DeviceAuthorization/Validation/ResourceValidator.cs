// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
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
        var scope = context.ClientInfo.ScopeServedFor(request.Scope ?? []) ?? [];

        var refusal = PolledRequestResources.Settle(
            resourceManager,
            tenant,
            context.ClientInfo,
            request.Resources,
            scope,
            out var resources);
        if (refusal is not null)
            return refusal;

        context.Resources = resources;
        return null;
    }
}
