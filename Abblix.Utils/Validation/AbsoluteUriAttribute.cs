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

using System.ComponentModel.DataAnnotations;

namespace Abblix.Utils.Validation;

/// <summary>
/// A validation attribute that requires the value to be an absolute URI and, optionally, to use a specific scheme.
/// Absence is valid — combine with <see cref="RequiredAttribute"/> to also reject a missing value. Shared by the MVC
/// and Minimal API OIDC server adapters, whose source generators emit it (with the marker's scheme argument) from the
/// declarative core <c>AbsoluteUri</c> marker.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public sealed class AbsoluteUriAttribute(string? requireScheme = null) : ValidationAttribute
{
    /// <summary>The URI scheme the value must use (e.g. "https"); any absolute scheme is accepted when null.</summary>
    public string? RequireScheme { get; set; } = requireScheme;

    /// <inheritdoc />
    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        => value switch
        {
            null => ValidationResult.Success,
            string str when string.IsNullOrEmpty(str) => ValidationResult.Success,
            Uri uri when string.IsNullOrEmpty(uri.OriginalString) => ValidationResult.Success,

            string str when Uri.TryCreate(str, UriKind.RelativeOrAbsolute, out var uri)
                => IsValid(uri, validationContext),

            Uri { IsAbsoluteUri: true, Scheme: var scheme }
                when RequireScheme.HasValue() && !string.Equals(RequireScheme, scheme, StringComparison.OrdinalIgnoreCase)
                => new ValidationResult($"{validationContext.GetName()} value must use {RequireScheme} scheme."),

            Uri { IsAbsoluteUri: true } => ValidationResult.Success,
            Uri => new ValidationResult($"{validationContext.GetName()} value is not absolute."),
            _ => new ValidationResult($"{validationContext.GetName()} is not Uri, but {value.GetType().Name}."),
        };
}
