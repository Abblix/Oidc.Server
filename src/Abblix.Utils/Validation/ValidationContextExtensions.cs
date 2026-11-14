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
/// Names the member a validation attribute refuses, as the client spelled it.
/// </summary>
internal static class ValidationContextExtensions
{
    /// <summary>
    /// Returns the member's wire name (its <see cref="JsonPropertyNameAttribute"/>) for use in validation messages,
    /// falling back to the context display name when the member declares none.
    /// </summary>
    /// <param name="context">The <see cref="ValidationContext"/> instance.</param>
    /// <returns>The wire name, or the display name when no <see cref="JsonPropertyNameAttribute"/> is present.</returns>
    public static string GetWireName(this ValidationContext context)
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
