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

namespace Abblix.DependencyInjection;

/// <summary>
/// Records the (service, composite) pairs produced by
/// <see cref="ServiceCollectionExtensions.Compose{TInterface,TComposite}"/>. A downstream integrity check reads
/// this to verify each composed singular still resolves to its composite and was not shadowed by a service
/// registered for the same contract after composition — which the last-wins singular resolve would otherwise
/// return, silently dropping the composed pipeline.
/// </summary>
public sealed class ComposedFamilyRegistry
{
    private readonly List<(Type Service, Type Composite)> _families = [];

    /// <summary>Records that <paramref name="serviceType"/> was composed into <paramref name="compositeType"/>.</summary>
    public void Record(Type serviceType, Type compositeType) => _families.Add((serviceType, compositeType));

    /// <summary>The composed families recorded so far.</summary>
    public IReadOnlyList<(Type Service, Type Composite)> Families => _families;
}
