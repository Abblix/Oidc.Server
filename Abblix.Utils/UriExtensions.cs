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

namespace Abblix.Utils;

/// <summary>
/// The UriExtensions class provides extension methods for the Uri class,
/// facilitating the manipulation of query strings and fragment parts of a URI.
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
