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
/// A validation attribute that restricts a string (or string-collection) value to a fixed set, matched exactly.
/// An absent value passes: whether a member is required is a separate question, asked by a separate attribute,
/// which is why the framework's own <c>AllowedValues</c> cannot stand in for this one - it refuses null.
/// Shared by the MVC and Minimal API OIDC server adapters, whose source generators emit it onto a generated model
/// whenever the corresponding core property carries the declarative <c>AllowedValues</c> marker.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public class AllowedValuesAttribute(params string[] allowedValues) : ValidationAttribute
{
    /// <inheritdoc />
    protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        => value switch
        {
            null => ValidationResult.Success,
            string[][] arrays => IsValid(arrays.SelectMany(array => array)),
            string[] values => IsValid(values),
            string single => IsValid(single),
            _ => throw new InvalidOperationException(
                $"The type {value.GetType()} is not supported by {nameof(AllowedValuesAttribute)}"),
        };

    private ValidationResult? IsValid(IEnumerable<string> values)
    {
        foreach (var value in values)
        {
            var result = IsValid(value);
            if (result != ValidationResult.Success)
                return result;
        }

        return ValidationResult.Success;
    }

    // Ordinal, because every value this attribute guards is a protocol name from an IANA registry, and those
    // are case-sensitive: RFC 7636 section 6.2.1 states "This name is case-sensitive" in the registration
    // template for code_challenge_method, whose two values section 4.2 spells "plain" and "S256". Matching
    // case-insensitively accepted "s256" and answered it as if the client had asked for the SHA-256 transform,
    // which is a value the client never sent.
    private ValidationResult? IsValid(string value)
        => allowedValues.Contains(value, StringComparer.Ordinal)
            ? ValidationResult.Success
            : new ValidationResult($"The value '{value}' is invalid");
}
