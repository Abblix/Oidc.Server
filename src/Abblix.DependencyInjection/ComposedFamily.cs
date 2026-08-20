// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.DependencyInjection;

/// <summary>
/// What a composition leaves in the collection under its family's <see cref="CompositionKey"/>. It carries
/// nothing: its presence is the whole message, and that message is the one thing about a composed family that
/// cannot be read off any other registration.
/// </summary>
/// <remarks>
/// Everything else about the family is derivable. The composite's own registration carries its lifetime and
/// survives what the family does to itself; the members name their own key. What no surviving registration can
/// say is that a composition happened at all: a plain registration of an interface whose implementation type is
/// also registered on its own is what an ordinary host writes with two calls, and the one shape that would give
/// it away - the factory this library wraps the composite in - is gone the moment anything decorates it.
/// <para>
/// A value rather than a ready-made cursor, because a cursor is bound to the collection it was built on while
/// descriptors are values that get copied between collections. Stored as an object, a copied family would hand
/// out a cursor over the collection it was composed on: edits would land in one collection while the caller
/// held the other, silently, and the member would be missing from the provider actually built.
/// </para>
/// </remarks>
internal sealed record ComposedFamily
{
    private ComposedFamily()
    {
    }

    /// <summary>The mark itself. It says one thing and holds no state, so one of it is enough.</summary>
    public static readonly ComposedFamily Instance = new();
}