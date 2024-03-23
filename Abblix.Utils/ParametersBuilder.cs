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
