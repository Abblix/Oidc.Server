﻿// Abblix OIDC Server Library
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
