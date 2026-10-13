// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
		// Only this package's models: the provider is registered for the whole application, and a host's own
		// model with a [Required] property binds as it would without this package
		if (context is { Key.ContainerType: { } container, PropertyAttributes: { } attributes } &&
		    container.Assembly == typeof(RequiredBindingMetadataProvider).Assembly &&
		    attributes.OfType<RequiredAttribute>().Any())
		{
			context.BindingMetadata.IsBindingRequired = true;
		}
	}
}
