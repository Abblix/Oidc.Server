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
