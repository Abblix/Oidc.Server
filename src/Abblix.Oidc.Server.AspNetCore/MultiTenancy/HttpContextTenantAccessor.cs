// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// The tenant <see cref="TenantResolutionMiddleware"/> resolved the current request to.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class HttpContextTenantAccessor(IHttpContextAccessor httpContextAccessor) : ITenantAccessor
{
    /// <inheritdoc />
    public TenantContext? Current => httpContextAccessor.HttpContext?.Features.Get<TenantContext>();
}
