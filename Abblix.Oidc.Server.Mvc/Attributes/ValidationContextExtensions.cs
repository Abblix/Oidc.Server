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
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Attributes;

/// <summary>
/// Provides extension methods for <see cref="ValidationContext"/>.
/// </summary>
internal static class ValidationContextExtensions
{
	/// <summary>
	/// Retrieves the name of the member associated with the validation context,
	/// taking into account custom attributes that might alter the displayed name.
	/// </summary>
	/// <param name="context">The <see cref="ValidationContext"/> instance.</param>
	/// <returns>
	/// The name of the member for display purposes. This could be the value set in
	/// <see cref="BindPropertyAttribute"/> or <see cref="JsonPropertyNameAttribute"/>, if they are applied.
	/// Otherwise, it defaults to the display name provided by the context.
	/// </returns>
	/// <remarks>
	/// This method first checks if the member has a <see cref="BindPropertyAttribute"/> or
	/// <see cref="JsonPropertyNameAttribute"/> applied, and if so, returns the specified name.
	/// If these attributes are not present, it falls back to the default display name.
	/// </remarks>
	public static string? GetName(this ValidationContext context)
	{
		if (context.MemberName == null)
			return null;

		var member = context.ObjectType.GetMember(context.MemberName).SingleOrDefault();

		return member switch
		{
			not null when member.GetCustomAttribute<BindPropertyAttribute>() is { Name: var name } => name,
			not null when member.GetCustomAttribute<JsonPropertyNameAttribute>() is { Name: var name } => name,
			_ => context.DisplayName,
		};
	}
}
