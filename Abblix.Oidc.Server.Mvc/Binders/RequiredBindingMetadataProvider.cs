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
