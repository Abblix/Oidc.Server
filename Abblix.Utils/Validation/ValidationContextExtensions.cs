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
using System.Reflection;
using System.Text.Json.Serialization;

namespace Abblix.Utils.Validation;

/// <summary>
/// Extension methods for <see cref="ValidationContext"/> shared by the validation attributes in this namespace.
/// </summary>
internal static class ValidationContextExtensions
{
    /// <summary>
    /// Returns the member's wire name (its <see cref="JsonPropertyNameAttribute"/>) for use in validation messages,
    /// falling back to the context display name when the member declares none.
    /// </summary>
    /// <param name="context">The <see cref="ValidationContext"/> instance.</param>
    /// <returns>The wire name, or the display name when no <see cref="JsonPropertyNameAttribute"/> is present.</returns>
    public static string? GetName(this ValidationContext context)
    {
        if (context.MemberName == null)
            return context.DisplayName;

        var member = context.ObjectType.GetMember(context.MemberName).SingleOrDefault();
        return member?.GetCustomAttribute<JsonPropertyNameAttribute>() is { Name: var name }
            ? name
            : context.DisplayName;
    }
}
