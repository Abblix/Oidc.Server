// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

// The tenant a span names is read from the multi-tenancy feature where it is in use
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// Handles a request of the userinfo endpoint in a span of <see cref="TelemetryEndpoints.UserInfo"/>.
/// </summary>
/// <param name="inner">The handler of the endpoint.</param>
/// <param name="tenants">Tells the tenant serving the request, under multi-tenancy.</param>
internal sealed class TracedUserInfoHandler(
    IUserInfoHandler inner,
    ITenantAccessor? tenants = null) : IUserInfoHandler
{
    /// <inheritdoc />
    public Task<Result<UserInfoFoundResponse, OidcError>> HandleAsync(UserInfoRequest userInfoRequest, ClientRequest clientRequest)
        => EndpointSpan.RunAsync(
            TelemetryEndpoints.UserInfo,
            tenants,
            () => inner.HandleAsync(userInfoRequest, clientRequest),
            EndpointSpan.ErrorOf);
}
