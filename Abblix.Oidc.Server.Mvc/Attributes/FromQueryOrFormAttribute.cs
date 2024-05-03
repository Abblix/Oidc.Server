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

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Abblix.Oidc.Server.Mvc.Attributes;

/// <summary>
/// An attribute that specifies binding from either the query string or the form data.
/// </summary>
/// <remarks>
/// This attribute is useful in scenarios where a value can be provided either through the query string or form data.
/// It implements <see cref="IBindingSourceMetadata"/> and extends <see cref="BindAttribute"/>.
/// </remarks>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Parameter)]
public class FromQueryOrFormAttribute : BindAttribute, IBindingSourceMetadata
{
	/// <summary>
	/// Initializes a new instance of the <see cref="FromQueryOrFormAttribute"/> class.
	/// </summary>
	/// <remarks>
	/// By default, the prefix is set to an empty string, indicating no specific prefix for the bound properties.
	/// </remarks>
	public FromQueryOrFormAttribute()
	{
		Prefix = "";
	}

	/// <summary>
	/// Gets the binding source for this attribute, combining both Query and Form sources.
	/// </summary>
	/// <remarks>
	/// Specifies that the binding source is a composite of both Query and Form sources.
	/// </remarks>
	public BindingSource BindingSource => CompositeBindingSource.Create(
		new[]
		{
			BindingSource.Query,
			BindingSource.Form,
		},
		nameof(FromQueryOrFormAttribute));
}
