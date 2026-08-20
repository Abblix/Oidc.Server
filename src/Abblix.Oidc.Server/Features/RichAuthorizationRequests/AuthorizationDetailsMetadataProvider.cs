// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.RichAuthorizationRequests;

/// <summary>
/// Default implementation of <see cref="IAuthorizationDetailsMetadataProvider"/>. Enumerates
/// every keyed <see cref="IAuthorizationDetailValidator"/> registration via
/// <see cref="KeyedService.AnyKey"/> (.NET 8+) and projects each instance's
/// <see cref="IAuthorizationDetailValidator.Type"/>, so discovery's
/// <c>authorization_details_types_supported</c> list always reflects exactly the per-type
/// validators the host currently has registered - no separate config to keep in sync.
/// </summary>
internal sealed class AuthorizationDetailsMetadataProvider(
    IServiceProvider serviceProvider) : IAuthorizationDetailsMetadataProvider
{
    /// <inheritdoc/>
    public IEnumerable<string>? SupportedTypes
    {
        get
        {
            var types = serviceProvider
                .GetKeyedServices<IAuthorizationDetailValidator>(KeyedService.AnyKey)
                .Select(v => v.Type)
                .ToArray();

            return types.Length != 0 ? types : null;
        }
    }
}
