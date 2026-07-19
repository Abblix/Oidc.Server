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

namespace Abblix.Utils.Validation;

/// <summary>
/// A validation attribute that rejects a collection containing a null element; a non-collection value is left
/// untouched. Shared by the MVC and Minimal API OIDC server adapters, whose source generators emit it from the
/// declarative core <c>ElementsRequired</c> marker.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter)]
public sealed class ElementsRequiredAttribute : ValidationAttribute
{
    /// <inheritdoc />
    public override bool IsValid(object? value)
        => value switch
        {
            IEnumerable collection => collection.Cast<object?>().All(item => item != null),
            _ => true,
        };

    /// <inheritdoc />
    public override string FormatErrorMessage(string name) => $"Each element of the {name} must be non-null.";
}
