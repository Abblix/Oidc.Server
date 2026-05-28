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

namespace Abblix.Oidc.Server.Features.TokenExchange;

/// <summary>
/// Default implementation of <see cref="ISubjectTokenTypesMetadataProvider"/>. Enumerates every
/// keyed <see cref="ISubjectTokenResolver"/> registration via <see cref="KeyedService.AnyKey"/>
/// and projects each instance's <see cref="ISubjectTokenResolver.Type"/>, so discovery's
/// <c>subject_token_types_supported</c> list always reflects exactly the resolvers the host
/// currently has registered -- including any custom ones the host added for non-native formats
/// (SAML, broker tokens, etc.) -- without a separate config to keep in sync.
/// </summary>
internal sealed class SubjectTokenTypesMetadataProvider(
    IServiceProvider serviceProvider) : ISubjectTokenTypesMetadataProvider
{
    /// <inheritdoc/>
    public IEnumerable<string>? SupportedTypes
    {
        get
        {
            // Each resolver publishes a set of URIs via SupportedTypes (default: [Type] for
            // single-URI resolvers; JwtSubjectTokenResolver overrides to publish all three of
            // access_token / id_token / jwt that share one validation path). Enumeration via
            // KeyedService.AnyKey returns one instance per keyed registration so a multi-key
            // resolver shows up multiple times; Distinct collapses the duplicates.
            var types = serviceProvider
                .GetKeyedServices<ISubjectTokenResolver>(KeyedService.AnyKey)
                .SelectMany(r => r.SupportedTypes)
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            return types.Length != 0 ? types : null;
        }
    }
}
