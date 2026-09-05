// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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