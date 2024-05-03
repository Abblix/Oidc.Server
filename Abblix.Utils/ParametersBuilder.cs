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

using System.Collections.Specialized;
using System.Web;



namespace Abblix.Utils;

/// <summary>
/// Provides a builder for constructing and manipulating query strings or URI fragment parts.
/// </summary>
public class ParametersBuilder
{
	/// <summary>
	/// Initializes a new instance of the <see cref="ParametersBuilder"/> class.
	/// </summary>
	/// <param name="valuesString">A string representing the initial query string or URI fragment.</param>
	public ParametersBuilder(string valuesString = "")
	{
		_values = HttpUtility.ParseQueryString(valuesString);
	}

	private readonly NameValueCollection _values;

	/// <summary>
	/// Gets or sets the value associated with the specified parameter name.
	/// </summary>
	/// <param name="name">The name of the parameter to get or set.</param>
	/// <returns>The value associated with the specified name.</returns>
	public string? this[string name]
	{
		get => _values[name];
		set => _values[name] = value;
	}

	/// <summary>
	/// Returns a string that represents the current query string or URI fragment.
	/// </summary>
	/// <returns>A string that represents the current state of the builder.</returns>
	public override string ToString() => _values.ToString() ?? string.Empty;

	/// <summary>
	/// Clears all the parameters from the builder.
	/// </summary>
	public void Clear() => _values.Clear();
}
