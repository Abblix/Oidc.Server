// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.AuthorizationDetails;

/// <summary>
/// Default implementation of <see cref="IAuthorizationDetailsMetadataProvider"/>. Enumerates
/// every keyed <see cref="IAuthorizationDetailValidator"/> registration via
/// <see cref="KeyedService.AnyKey"/> (.NET 8+) and projects each instance's
/// <see cref="IAuthorizationDetailValidator.Type"/>, so discovery's
/// <c>authorization_details_types_supported</c> list always reflects exactly the per-type
/// validators the host currently has registered — no separate config to keep in sync.
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

            return types.Length == 0 ? null : types;
        }
    }
}
