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

namespace Abblix.DependencyInjection;

/// <summary>
/// Identifies one composed family: the interface it is a family of, plus the service key when the family lives
/// under one. It is the service key of both things a composition leaves in the collection - the member
/// registrations and the cursor over them - so a family is found by one key comparison and same-interface
/// families under different keys never meet.
/// </summary>
/// <remarks>
/// Being internal, it is also what makes a member unforgeable: nothing outside this assembly can register a
/// descriptor that a cursor would mistake for a member of a family it composed, and a host keying a service of
/// the same interface by a name of its own stays its own business.
/// </remarks>
/// <param name="InterfaceType">The family interface.</param>
/// <param name="ServiceKey">The key a keyed family lives under, or null for a plain family.</param>
internal sealed record CompositionKey(Type InterfaceType, object? ServiceKey);

/// <summary>
/// What a composition leaves in the collection under its family's <see cref="CompositionKey"/>: the presence
/// of the entry is what makes the family composed, and it carries the composite's lifetime, which is the one
/// thing about the family a cursor cannot derive.
/// </summary>
/// <remarks>
/// A value rather than a ready-made cursor, because a cursor is bound to the collection it was built on while
/// descriptors are values that get copied between collections. Stored as an object, a copied family would hand
/// out a cursor over the collection it was composed on: edits would land in one collection while the caller
/// held the other, silently, and the member would be missing from the provider actually built.
/// </remarks>
/// <param name="Lifetime">The lifetime the composite was registered with, which its members must not undercut.</param>
internal sealed record ComposedFamily(ServiceLifetime Lifetime);
