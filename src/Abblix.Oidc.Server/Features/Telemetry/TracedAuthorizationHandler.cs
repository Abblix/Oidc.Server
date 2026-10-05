// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

// The tenant a span names is read from the multi-tenancy feature where it is in use
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Handles a request of the authorization endpoint in a span of <see cref="TelemetryEndpoints.Authorize"/>.
/// </summary>
/// <param name="inner">The handler of the endpoint.</param>
/// <param name="tenants">Tells the tenant serving the request, under multi-tenancy.</param>
internal sealed class TracedAuthorizationHandler(
    IAuthorizationHandler inner,
    ITenantAccessor? tenants = null) : IAuthorizationHandler
{
    /// <inheritdoc />
    public Task<Endpoints.Authorization.Interfaces.AuthorizationResponse> HandleAsync(Model.AuthorizationRequest request)
        => EndpointSpan.RunAsync(
            TelemetryEndpoints.Authorize,
            tenants,
            () => inner.HandleAsync(request),
            EndpointSpan.ErrorOf,
            () => (TelemetryTags.ResponseType, EndpointSpan.ResponseTypeOf(request.ResponseType)));
}
