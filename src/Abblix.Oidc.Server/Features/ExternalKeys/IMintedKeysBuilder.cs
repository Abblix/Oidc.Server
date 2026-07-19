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

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// The continuation of <c>UseKeysInProcess</c>: the tier that mints its own keys must say where the ring lives,
/// and the packages hang their <c>PersistRingTo...</c> calls off this.
/// </summary>
/// <remarks>
/// A ring store belongs to this tier and to no other, so it attaches here rather than to the service collection:
/// there is nothing to register a store onto unless the tier that needs one was chosen. The tier where the
/// custodian holds every key has no ring at all.
/// </remarks>
public interface IMintedKeysBuilder
{
    /// <summary>The collection a <c>PersistRingTo...</c> call registers the store into.</summary>
    IServiceCollection Services { get; }
}
