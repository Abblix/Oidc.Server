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
