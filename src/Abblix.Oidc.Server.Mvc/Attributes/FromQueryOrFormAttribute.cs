// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
		[
			BindingSource.Query,
			BindingSource.Form
		],
		nameof(FromQueryOrFormAttribute));
}
