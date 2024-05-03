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

using System.Collections;
using System.ComponentModel.DataAnnotations;

namespace Abblix.Oidc.Server.Mvc.Attributes;

/// <summary>
/// An attribute that ensures all elements within an enumerable collection are non-null.
/// </summary>
/// <remarks>
/// Use this attribute to validate that collections do not contain any null elements.
/// It extends the standard <see cref="ValidationAttribute"/> and overrides the <see cref="IsValid"/> method.
/// </remarks>
public sealed class ElementsRequiredAttribute : ValidationAttribute
{
    /// <summary>
    /// Determines whether the specified value of the object is valid.
    /// </summary>
    /// <param name="value">The value of the object to validate.</param>
    /// <returns>
    /// <c>true</c> if the value is either not an enumerable collection, or if it's a collection with all non-null elements;
    /// otherwise, <c>false</c>.
    /// </returns>
    public override bool IsValid(object? value)
        => value switch
        {
            IEnumerable collection => collection.Cast<object?>().All(item => item != null),
            _ => true,
        };

    /// <summary>
    /// Formats the error message to display if the validation fails.
    /// </summary>
    /// <param name="name">The name to include in the formatted message.</param>
    /// <returns>A string containing the formatted error message.</returns>
    public override string FormatErrorMessage(string name)
        => $"Each element of the {name} must be non-null.";
}
