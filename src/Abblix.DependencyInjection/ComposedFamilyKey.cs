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
/// The service key that members of a composed keyed family are stored under: pairs the family's original
/// service key with the composite type. The pairing keeps same-interface families under different keys
/// isolated (even when they share the composite class) and keeps the descriptors self-describing - both
/// the original key and the composite type are recoverable from any member, so no side registry exists.
/// </summary>
/// <param name="ServiceKey">The service key the family was composed under.</param>
/// <param name="CompositeType">The composite type the family was composed into.</param>
public sealed record ComposedFamilyKey(object ServiceKey, Type CompositeType);
