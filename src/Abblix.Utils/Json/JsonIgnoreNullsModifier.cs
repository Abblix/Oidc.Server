// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization.Metadata;

namespace Abblix.Utils.Json;

/// <summary>
/// Provides a <see cref="JsonTypeInfo"/> modifier that enforces null-omission for all nullable
/// properties of types decorated with <see cref="JsonIgnoreNullsAttribute"/>.
/// </summary>
/// <remarks>
/// Register <see cref="Apply"/> via
/// <see cref="System.Text.Json.JsonSerializerOptions.TypeInfoResolverChain"/> to activate the attribute:
/// <code>
/// options.TypeInfoResolverChain.Add(
///     new DefaultJsonTypeInfoResolver { Modifiers = { JsonIgnoreNullsModifier.Apply } });
/// </code>
/// </remarks>
public static class JsonIgnoreNullsModifier
{
    /// <summary>
    /// A <see cref="JsonTypeInfo"/> modifier that sets <c>ShouldSerialize</c> to skip <c>null</c> values
    /// on every nullable property of any type decorated with <see cref="JsonIgnoreNullsAttribute"/>.
    /// </summary>
    public static void Apply(JsonTypeInfo typeInfo)
    {
        if (!typeInfo.Type.IsDefined(typeof(JsonIgnoreNullsAttribute), inherit: false))
            return;

        foreach (var property in typeInfo.Properties)
        {
            var propertyType = property.PropertyType;

            // Non-nullable value types (e.g. bool, int) can never be null - skip them.
            if (propertyType.IsValueType && Nullable.GetUnderlyingType(propertyType) == null)
                continue;

            // Compose with any existing ShouldSerialize delegate so that conditions
            // already set (e.g. from other modifiers) are respected.
            var existing = property.ShouldSerialize;
            property.ShouldSerialize = existing != null
                ? (obj, value) => value is not null && existing(obj, value)
                : (_, value) => value is not null;
        }
    }
}
