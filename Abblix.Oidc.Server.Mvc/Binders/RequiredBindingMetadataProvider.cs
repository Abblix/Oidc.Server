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
using Microsoft.AspNetCore.Mvc.ModelBinding.Metadata;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// Provides binding metadata based on the presence of the <see cref="RequiredAttribute"/> on model properties.
/// </summary>
/// <remarks>
/// This class implements the <see cref="IBindingMetadataProvider"/> interface and checks if a model property
/// is annotated with the <see cref="RequiredAttribute"/>. If so, it sets the binding metadata to indicate that
/// binding is required for that property.
/// </remarks>
public class RequiredBindingMetadataProvider : IBindingMetadataProvider
{
	/// <summary>
	/// Creates binding metadata for a given context. If a model property is marked with <see cref="RequiredAttribute"/>,
	/// this method sets the binding metadata to require binding for that property.
	/// </summary>
	/// <param name="context">The context for the binding metadata provider.</param>
	/// <remarks>
	/// The method checks for the presence of <see cref="RequiredAttribute"/> in the property attributes of the context.
	/// If found, it sets <see cref="BindingMetadata.IsBindingRequired"/> to true, enforcing the requirement for binding.
	/// </remarks>
	public void CreateBindingMetadata(BindingMetadataProviderContext context)
	{
		if (context is { PropertyAttributes: { } attributes } &&
		    attributes.OfType<RequiredAttribute>().Any())
		{
			context.BindingMetadata.IsBindingRequired = true;
		}
	}
}
