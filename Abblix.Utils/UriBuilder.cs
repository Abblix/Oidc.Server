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
/// A wrapper around System.UriBuilder, providing enhanced functionality for URI manipulation,
/// specifically for handling query strings and fragments.
/// </summary>
public class UriBuilder
{
    /// <summary>
    /// Initializes a new instance of the UriBuilder class with the specified Uri instance.
    /// </summary>
    /// <param name="uri">The Uri instance to use as the base of the UriBuilder.</param>
    public UriBuilder(Uri uri)
        : this(new System.UriBuilder(uri))
    {
    }

    /// <summary>
    /// Initializes a new instance of the UriBuilder class with the specified URI string.
    /// </summary>
    /// <param name="uri">A URI string to use as the base of the UriBuilder.</param>
    public UriBuilder(string uri)
        : this(new System.UriBuilder(uri))
    {
    }

    /// <summary>
    /// Internal constructor that initializes the UriBuilder with a System.UriBuilder instance.
    /// </summary>
    /// <param name="builder">The System.UriBuilder instance to wrap.</param>
    private UriBuilder(System.UriBuilder builder)
    {
        _builder = builder;
        Query = new ParametersBuilder(_builder.Query);
        Fragment = new ParametersBuilder(_builder.Fragment);
    }

    private readonly System.UriBuilder _builder;

    /// <summary>
    /// Gets the ParametersBuilder for the query string.
    /// </summary>
    public ParametersBuilder Query { get; }

    /// <summary>
    /// Gets the ParametersBuilder for the fragment part of the URI.
    /// </summary>
    public ParametersBuilder Fragment { get; }

    /// <summary>
    /// Gets the URI constructed by the UriBuilder.
    /// </summary>
    public Uri Uri
    {
        get
        {
            _builder.Query = Query.ToString();
            _builder.Fragment = Fragment.ToString();
            return _builder.Uri;
        }
    }

    /// <summary>
    /// Converts a UriBuilder instance to a Uri.
    /// </summary>
    /// <param name="builder">The UriBuilder instance to convert.</param>
    public static implicit operator Uri(UriBuilder builder) => builder.Uri;

    /// <summary>
    /// Converts a UriBuilder instance to a string.
    /// </summary>
    /// <param name="builder">The UriBuilder instance to convert.</param>
    public static implicit operator string(UriBuilder builder) => builder.Uri.ToString();
}
