// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
	/// The value associated with the specified parameter name.
	/// </summary>
	/// <param name="name">The name of the parameter to get or set.</param>
	/// <returns>The value associated with the specified name.</returns>
	public string? this[string name]
	{
		get => _values[name];
		set => _values[name] = value;
	}

	/// <summary>
	/// Appends a value under a name, keeping any value already stored under it.
	/// </summary>
	/// <param name="name">The name of the parameter to append to.</param>
	/// <param name="value">The value to append.</param>
	/// <remarks>
	/// The indexer replaces, which is what almost every parameter wants. This is for the few that a
	/// specification allows to repeat (<c>resource</c> of RFC 8707, for one), where each occurrence carries
	/// its own meaning and replacing would silently drop all but the last.
	/// </remarks>
	public void Add(string name, string? value) => _values.Add(name, value);

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
