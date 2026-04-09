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

            // Non-nullable value types (e.g. bool, int) can never be null — skip them.
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
