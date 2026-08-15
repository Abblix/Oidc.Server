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

namespace Abblix.Jwt.ExternalKeys;

/// <inheritdoc />
/// <remarks>
/// The builder owns the policy rather than handing it straight to the ring, because a call after the placement can
/// still change it. The ring reads <see cref="Policy"/> when the container builds it, which is long after every
/// such call has run.
/// </remarks>
internal sealed class MintedKeysBuilder(IServiceCollection services, MintedKeys policy) : IMintedKeysBuilder
{
    /// <inheritdoc />
    public IServiceCollection Services { get; } = services;

    /// <summary>The policy as it stands, including whatever later calls have added to it.</summary>
    public MintedKeys Policy { get; private set; } = policy;

    /// <inheritdoc />
    public IMintedKeysBuilder AdoptExistingKeys(params JsonWebKey[] keys)
    {
        Policy = Policy with { AdoptedKeys = [..Policy.AdoptedKeys, ..keys] };
        return this;
    }
}
