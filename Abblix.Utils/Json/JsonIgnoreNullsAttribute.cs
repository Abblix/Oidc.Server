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

namespace Abblix.Utils.Json;

/// <summary>
/// Marks a class or struct so that all nullable properties are omitted from the serialized JSON
/// when their value is <c>null</c>, without requiring a per-property
/// <see cref="System.Text.Json.Serialization.JsonIgnoreAttribute"/> on each one.
/// </summary>
/// <remarks>
/// This attribute is a marker only. For it to take effect, the <see cref="System.Text.Json.JsonSerializerOptions"/>
/// used during serialization must have <see cref="JsonIgnoreNullsModifier.Apply"/> registered as a
/// <see cref="System.Text.Json.Serialization.Metadata.JsonTypeInfo"/> modifier — for example via
/// <see cref="System.Text.Json.Serialization.Metadata.DefaultJsonTypeInfoResolver.Modifiers"/> added to
/// <see cref="System.Text.Json.JsonSerializerOptions.TypeInfoResolverChain"/>.
/// Abblix's <c>AddOidcControllers</c> registers the modifier automatically.
/// </remarks>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct)]
public sealed class JsonIgnoreNullsAttribute : Attribute;
