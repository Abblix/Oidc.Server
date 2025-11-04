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

using Microsoft.AspNetCore.Http;

namespace Abblix.Utils;

/// <summary>
/// A wrapper around System.UriBuilder, providing enhanced functionality for URI manipulation,
/// specifically for handling query strings and fragments.
/// </summary>
public class UriBuilder
{
    /// <summary>
    /// Placeholder base URI used internally for relative URI handling.
    /// Required because System.UriBuilder only works with absolute URIs.
    /// This base is stripped out when returning relative URIs.
    /// </summary>
#pragma warning disable S1075 // URIs should not be hardcoded - This is a technical placeholder, not a configuration value
    private const string PlaceholderBase = "http://localhost/";
#pragma warning restore S1075

    /// <summary>
    /// Initializes a new instance of the UriBuilder class with the specified Uri instance.
    /// Supports both absolute and relative URIs.
    /// </summary>
    /// <param name="uri">The Uri instance to use as the base of the UriBuilder.</param>
    public UriBuilder(Uri uri)
        : this(uri.IsAbsoluteUri
            ? new System.UriBuilder(uri)
            : new System.UriBuilder(CombineWithPlaceholder(uri.OriginalString)),
            uri.OriginalString)
    {
        _isAbsoluteUri = uri.IsAbsoluteUri;
    }

    /// <summary>
    /// Initializes a new instance of the UriBuilder class with the specified URI string.
    /// Automatically detects and handles both absolute URIs and relative paths.
    /// </summary>
    /// <param name="uri">A URI string to use as the base of the UriBuilder.
    /// Can be an absolute URI (e.g., "https://example.com/path") or a relative path (e.g., "/path").</param>
    public UriBuilder(string uri)
        : this(new Uri(uri, UriKind.RelativeOrAbsolute))
    {
    }

    /// <summary>
    /// Internal constructor that initializes the UriBuilder with a System.UriBuilder instance.
    /// </summary>
    /// <param name="builder">The System.UriBuilder instance to wrap.</param>
    /// <param name="originalRelativePath">The original relative path without the placeholder base, if applicable.</param>
    private UriBuilder(System.UriBuilder builder, string? originalRelativePath = null)
    {
        _builder = builder;
        _originalRelativePath = originalRelativePath;
        Query = new ParametersBuilder(_builder.Query);
        Fragment = new ParametersBuilder(_builder.Fragment);
    }

    private readonly System.UriBuilder _builder;
    private readonly bool _isAbsoluteUri;
    private readonly string? _originalRelativePath;

    /// <summary>
    /// Combines the placeholder base URI with a relative path, avoiding double slashes.
    /// PlaceholderBase ends with '/', so skip leading '/' from relativePath if present.
    /// </summary>
    /// <param name="relativePath">The relative path to combine with the placeholder base.</param>
    /// <returns>A valid absolute URI string combining the placeholder base with the relative path.</returns>
    private static string CombineWithPlaceholder(string relativePath)
        => PlaceholderBase + (relativePath.StartsWith('/')
            ? relativePath[1..]  // Skip leading slash to avoid "http://localhost//path"
            : relativePath);     // No leading slash, just append

    /// <summary>
    /// The path part of the URI.
    /// </summary>
    public PathString Path
    {
        get => new(_builder.Path);
        set => _builder.Path = value.Value;
    }

    /// <summary>
    /// ParametersBuilder for the query string.
    /// </summary>
    public ParametersBuilder Query { get; }

    /// <summary>
    /// ParametersBuilder for the fragment part of the URI.
    /// </summary>
    public ParametersBuilder Fragment { get; }

    /// <summary>
    /// The URI constructed by the UriBuilder.
    /// For relative URIs, returns the path, query, and fragment without scheme and host.
    /// </summary>
    public Uri Uri
    {
        get
        {
            _builder.Query = Query.ToString();
            _builder.Fragment = Fragment.ToString();

            // Remove default port to avoid explicit port in URI (e.g., https://example.com:443/)
            // System.UriBuilder includes port even when it's default, which creates verbose URIs
            _builder.Port = (_builder.Uri.Scheme, _builder.Port) switch
            {
                ("http", 80) or
                ("https", 443) or
                ("ftp", 21) => -1, // -1 tells UriBuilder to omit the port from output
                _ => _builder.Port,
            };

            var uri = _builder.Uri;
            if (_isAbsoluteUri)
                return uri;

            // For relative URIs, preserve the original form (with or without leading slash)
            var pathAndQuery = uri.PathAndQuery + uri.Fragment;

            // If we have an original relative path and it didn't start with '/',
            // strip the leading '/' we added for the placeholder
            if (_originalRelativePath != null && !_originalRelativePath.StartsWith('/') && pathAndQuery.StartsWith('/'))
            {
                return new Uri(pathAndQuery[1..], UriKind.Relative);
            }

            return new Uri(pathAndQuery, UriKind.Relative);
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
