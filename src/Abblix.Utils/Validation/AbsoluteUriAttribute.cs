// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.ComponentModel.DataAnnotations;
using System.Reflection;
using System.Text.Json.Serialization;

namespace Abblix.Utils.Validation;

/// <summary>
/// A validation attribute that requires the value to be an absolute URI and, optionally, to use a specific scheme.
/// Absence is valid - combine with <see cref="RequiredAttribute"/> to also reject a missing value. Shared by the MVC
/// and Minimal API OIDC server adapters, whose source generators emit it (with the marker's scheme argument) from the
/// declarative core <c>AbsoluteUri</c> marker.
/// <param name="requireScheme">
/// The URI scheme the value must use (e.g. "https"); any absolute scheme is accepted when null.</param>
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public sealed class AbsoluteUriAttribute(string? requireScheme = null) : ValidationAttribute
{
    /// <inheritdoc />
    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext) => value switch
    {
        null => ValidationResult.Success,

        string str when string.IsNullOrEmpty(str) => ValidationResult.Success,
        Uri uri when string.IsNullOrEmpty(uri.OriginalString) => ValidationResult.Success,

        string str when Uri.TryCreate(str, UriKind.RelativeOrAbsolute, out var uri)
            => IsValid(uri, validationContext),

        Uri { IsAbsoluteUri: true, Scheme: var scheme }
            when requireScheme.HasValue() && !string.Equals(requireScheme, scheme, StringComparison.OrdinalIgnoreCase)
            => new ValidationResult($"{GetName(validationContext)} value must use {requireScheme} scheme."),

        Uri { IsAbsoluteUri: true } => ValidationResult.Success,
        Uri => new ValidationResult($"{GetName(validationContext)} value is not absolute."),

        _ => new ValidationResult($"{GetName(validationContext)} is not Uri, but {value.GetType().Name}."),
    };

    /// <summary>
    /// Returns the member's wire name (its <see cref="JsonPropertyNameAttribute"/>) for use in validation messages,
    /// falling back to the context display name when the member declares none.
    /// </summary>
    /// <param name="context">The <see cref="ValidationContext"/> instance.</param>
    /// <returns>The wire name, or the display name when no <see cref="JsonPropertyNameAttribute"/> is present.</returns>
    private static string GetName(ValidationContext context)
    {
        if (context.MemberName != null)
        {
            var member = context.ObjectType.GetMember(context.MemberName).SingleOrDefault();
            if (member?.GetCustomAttribute<JsonPropertyNameAttribute>() is { Name: var name })
                return name;
        }

        return context.DisplayName;
    }
}
