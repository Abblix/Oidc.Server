// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils.Json;

/// <summary>
/// Marks a class or struct so that all nullable properties are omitted from the serialized JSON
/// when their value is <c>null</c>, without requiring a per-property
/// <see cref="System.Text.Json.Serialization.JsonIgnoreAttribute"/> on each one.
/// </summary>
/// <remarks>
/// This attribute is a marker only. For it to take effect, the <see cref="System.Text.Json.JsonSerializerOptions"/>
/// used during serialization must have <see cref="JsonIgnoreNullsModifier.Apply"/> registered as a
/// <see cref="System.Text.Json.Serialization.Metadata.JsonTypeInfo"/> modifier - for example via
/// <see cref="System.Text.Json.Serialization.Metadata.DefaultJsonTypeInfoResolver.Modifiers"/> added to
/// <see cref="System.Text.Json.JsonSerializerOptions.TypeInfoResolverChain"/>.
/// Abblix's <c>AddOidcControllers</c> registers the modifier automatically.
/// </remarks>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct)]
public sealed class JsonIgnoreNullsAttribute : Attribute;
