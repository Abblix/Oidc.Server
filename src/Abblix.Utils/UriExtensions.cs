// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils;

/// <summary>
/// Helpers for adding parameters to a URI's query or fragment and for extracting standard parts (origin, trailing
/// slash). Empty or null parameter values are dropped rather than serialized as bare keys, matching the OAuth
/// 2.0 / OpenID Connect convention for absent parameters.
/// </summary>
public static class UriExtensions
{
	/// <summary>
	/// Adds parameters to the query string of the given URI.
	/// </summary>
	/// <param name="uri">The URI to which the query parameters will be added.</param>
	/// <param name="parameters">An array of tuples containing parameter names and values.</param>
	/// <returns>A string representing the URI with added query parameters.</returns>
	public static string AddToQuery(this Uri uri, (string, string?)[] parameters)
	{
		var builder = new UriBuilder(uri);
		builder.Query.AddNotEmptyParameters(parameters);
		return builder;
	}

	/// <summary>
	/// Adds parameters to the fragment part of the given URI.
	/// </summary>
	/// <param name="uri">The URI to which the fragment parameters will be added.</param>
	/// <param name="parameters">An array of tuples containing parameter names and values.</param>
	/// <returns>A string representing the URI with added fragment parameters.</returns>
	public static string AddToFragment(this Uri uri, (string, string?)[] parameters)
	{
		var builder = new UriBuilder(uri);
		builder.Fragment.AddNotEmptyParameters(parameters);
		return builder;
	}

	/// <summary>
	/// Adds non-empty parameters to a ParametersBuilder instance.
	/// </summary>
	/// <param name="builder">The ParametersBuilder to which the parameters will be added.</param>
	/// <param name="parameters">An array of tuples containing parameter names and values.</param>
	private static void AddNotEmptyParameters(this ParametersBuilder builder, (string, string?)[] parameters)
	{
		foreach (var (name, value) in parameters)
		{
			if (value.HasValue())
			{
				builder[name] = value;
			}
		}
	}

	/// <summary>
	/// Retrieves the origin (scheme, host, and optionally port) of the given URI.
	/// </summary>
	/// <param name="uri">The URI from which the origin will be extracted.</param>
	/// <returns>A string representing the origin of the URI.</returns>
	public static string GetOrigin(this Uri uri)
	{
		var originComponents = UriComponents.Scheme | UriComponents.Host;

		if (!uri.IsDefaultPort)
		{
			originComponents |= UriComponents.Port;
		}

		return uri.GetComponents(originComponents, UriFormat.Unescaped);
	}

	/// <summary>
	/// Appends a trailing slash to a URI string if it does not already end with one.
	/// </summary>
	/// <param name="uri">The URI string to which a trailing slash will be appended.</param>
	/// <returns>A string representing the URI with a trailing slash.</returns>
	public static string AppendTrailingSlash(this string uri) => uri.EndsWith('/') ? uri : uri + "/";
}
