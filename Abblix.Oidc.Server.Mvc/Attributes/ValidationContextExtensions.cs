// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
