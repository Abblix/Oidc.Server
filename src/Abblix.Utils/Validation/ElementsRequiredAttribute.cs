// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
