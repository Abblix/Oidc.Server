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
/// isolated, even when they share the composite class, and keeps every member self-describing.
/// </summary>
/// <param name="ServiceKey">The service key the family was composed under.</param>
/// <param name="CompositeType">The composite type the family was composed into.</param>
public sealed record ComposedFamilyKey(object ServiceKey, Type CompositeType);

/// <summary>
/// Identifies a family within a service collection: the interface it is a family of, plus the service key when
/// it is a keyed family. Used as the service key of the <see cref="ComposedFamily"/> entry, so looking a family
/// up is one key comparison rather than a search for something that looks like a composite.
/// </summary>
/// <param name="InterfaceType">The family interface.</param>
/// <param name="ServiceKey">The key a keyed family lives under, or null for a plain family.</param>
internal sealed record ComposedFamilyId(Type InterfaceType, object? ServiceKey);

/// <summary>
/// What a composition stores in the collection: the composite it built, keyed by <see cref="ComposedFamilyId"/>.
/// </summary>
/// <remarks>
/// The member registrations carry the composite in their own service keys, so for a populated family this entry
/// says nothing new. It is not redundant for an empty one: the members can be removed through the cursor while
/// the composite stays registered, and then the members no longer name anything. Inferred from them instead, an
/// emptied family reads as never composed, and the composite - a plain registration of the interface - is taken
/// for a member of the family it heads. Stored, the fact survives its own members.
/// </remarks>
/// <param name="CompositeType">The composite the family was composed into.</param>
internal sealed record ComposedFamily(Type CompositeType);
