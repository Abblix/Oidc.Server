// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Helpers that turn raw request values into the shapes the OIDC request models expect. They reproduce, in plain code,
/// what the MVC custom model binders do (space-separated lists, seconds to <see cref="TimeSpan"/>, JSON in a single
/// field, culture lists), so each model's <c>BindAsync</c> can call them. The core overloads take
/// <see cref="StringValues"/> so they work equally for form fields and query parameters; the <see cref="IFormCollection"/>
/// overloads are conveniences for the form-only models.
/// </summary>
internal static class FormValues
{
    /// <summary>A single value, or null when absent, empty or whitespace alone.</summary>
    /// <remarks>
    /// RFC 6749 section 3.1 puts this in the request direction as a requirement rather than a preference:
    /// "Parameters sent without a value MUST be treated as if they were omitted from the request." A query
    /// string carries no way to say "present and empty" that differs from saying nothing, so binding
    /// "state=" as an empty string invented a value the client never sent - and state is returned only if
    /// it was present in the request, so the client got back one it never issued. Whitespace alone counts as
    /// no value too, which is how ASP.NET Core's own model binding reads it, so the MVC host and this one
    /// answer the same request the same way.
    /// </remarks>
    public static string? Value(StringValues values)
        => values is { Count: 1 } && values.ToString() is var value && !string.IsNullOrWhiteSpace(value)
            ? value
            : null;

    /// <summary>A single value read from the form by name.</summary>
    public static string? Value(IFormCollection form, string name) => Value(Get(form, name));

    /// <summary>
    /// A single value as sent, whitespace kept, or null when absent or empty: what a typed reader parses, so a value
    /// of whitespace alone reaches it and is refused as one it cannot read rather than taken as absent.
    /// </summary>
    private static string? Sent(StringValues values)
        => values is { Count: 1 } && values.ToString() is { Length: > 0 } value ? value : null;

    /// <summary>
    /// The names among <paramref name="names"/> that <paramref name="source"/> carries more than once, counting the
    /// query and the form together. A value read above from a repeated parameter is no value, so the reading never
    /// joins two values into one, and the validation filter refuses the request naming these.
    /// </summary>
    public static string[] Repeated(RequestValues source, string[] names)
        => Array.FindAll(names, name => source.Count(name) > 1);

    /// <inheritdoc cref="Repeated(RequestValues, string[])"/>
    public static string[] Repeated(IFormCollection source, string[] names)
        => Array.FindAll(names, name => Get(source, name).Count > 1);

    /// <summary>A repeated field as an array (RFC 8707 <c>resource</c>/<c>audience</c>), or null.</summary>
    /// <remarks>
    /// Valueless entries are dropped for the reason given on <see cref="Value(StringValues)"/>, and a field
    /// whose every entry was valueless is the field not being there. Repeating the reading here rather than
    /// leaving it to the callers keeps one answer to "what does present-but-empty mean" for the whole
    /// binding surface.
    /// </remarks>
    public static string[]? Strings(StringValues values)
        => values is { Count: > 0 }
           && values.OfType<string>().Where(value => !string.IsNullOrWhiteSpace(value)).ToArray()
               is { Length: > 0 } strings
            ? strings
            : null;

    /// <summary>A repeated form field read by name as an array, or null.</summary>
    public static string[]? Strings(IFormCollection form, string name) => Strings(Get(form, name));

    /// <summary>A single space-separated value (e.g. <c>scope</c>) as an array; empty when absent.</summary>
    public static string[] SpaceSeparated(StringValues values)
    {
        var value = Value(values);
        return string.IsNullOrEmpty(value)
            ? []
            : value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>A single space-separated form value read by name as an array; empty when absent.</summary>
    public static string[] SpaceSeparated(IFormCollection form, string name) => SpaceSeparated(Get(form, name));

    /// <summary>A single space-separated value as an array, or null when absent (for optional list fields).</summary>
    public static string[]? SpaceSeparatedOrNull(StringValues values)
    {
        var value = Value(values);
        return string.IsNullOrEmpty(value)
            ? null
            : value.Split(' ', StringSplitOptions.RemoveEmptyEntries);
    }

    /// <summary>
    /// The posted form, or null when the request declares none or declares one the server cannot read, such as one
    /// past the form limits: the model records the latter and the validation filter refuses it, as the MVC host
    /// refuses a form its value provider cannot read.
    /// </summary>
    public static async Task<IFormCollection?> ReadFormAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        if (!request.HasFormContentType)
            return null;

        try
        {
            return await request.ReadFormAsync(cancellationToken);
        }
        catch (InvalidDataException)
        {
            return null;
        }
    }

    /// <summary>
    /// The value <paramref name="read"/> produces. A value it cannot read adds the parameter's name to
    /// <paramref name="malformed"/>, which the validation filter refuses before anything reads the model, so the
    /// default standing in for it is never seen.
    /// </summary>
    public static T Read<T>(Func<T> read, string name, List<string> malformed)
    {
        try
        {
            return read();
        }
        catch (FormatException)
        {
            malformed.Add(name);
            return default!;
        }
    }

    /// <summary>A single value parsed as a URI, or null when absent. A value that is not a URI is refused.</summary>
    public static Uri? ParseUri(StringValues values)
    {
        var value = Value(values);
        return value is null ? null : ToUri(value);
    }

    /// <summary>A single form value read by name as a URI, or null.</summary>
    public static Uri? ParseUri(IFormCollection form, string name) => ParseUri(Get(form, name));

    /// <summary>
    /// A repeated field as an array of URIs (RFC 8707 <c>resource</c>), or null when no entry is left. An entry that
    /// is empty or whitespace alone is no entry, as the MVC host reads it, and an entry that is not a URI is refused.
    /// </summary>
    public static Uri[]? ParseUris(StringValues values)
    {
        var uris = values.OfType<string>().Where(value => !string.IsNullOrWhiteSpace(value)).Select(ToUri).ToArray();
        return uris.Length > 0 ? uris : null;
    }

    /// <summary>A repeated form field read by name as an array of URIs, or null.</summary>
    public static Uri[]? ParseUris(IFormCollection form, string name) => ParseUris(Get(form, name));

    private static Uri ToUri(string value)
        => Uri.TryCreate(value, UriKind.RelativeOrAbsolute, out var uri) ? uri : throw MalformedValue();

    /// <summary>
    /// A single integer-seconds value as a <see cref="TimeSpan"/> (e.g. <c>max_age</c>), or null when absent. A value
    /// that is not a number of seconds is refused, as the MVC model binder refuses it.
    /// </summary>
    public static TimeSpan? Seconds(StringValues values)
    {
        var value = Sent(values);
        if (value is null)
            return null;

        if (!long.TryParse(value, out var seconds))
            throw MalformedValue();

        // A syntactically valid but out-of-range seconds value overflows TimeSpan. Shape it as a 400 rather than
        // letting the throw escape BindAsync as a 500 (mirrors the MVC model binder's catch-into-ModelState).
        try
        {
            return TimeSpan.FromSeconds(seconds);
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or OverflowException)
        {
            throw MalformedValue();
        }
    }

    /// <summary>A single space-separated locale list (e.g. <c>ui_locales</c>) as cultures, or null.</summary>
    public static CultureInfo[]? Cultures(StringValues values)
    {
        var value = Value(values);
        if (string.IsNullOrEmpty(value))
            return null;

        // An invalid BCP-47 tag throws; shape it as a 400 instead of a 500 escaping BindAsync.
        try
        {
            return value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(culture => new CultureInfo(culture))
                .ToArray();
        }
        catch (CultureNotFoundException)
        {
            throw MalformedValue();
        }
    }

    /// <summary>Deserializes a single field's JSON value (e.g. <c>claims</c>, <c>authorization_details</c>), or null.</summary>
    public static T? Json<T>(StringValues values)
    {
        var value = Sent(values);
        if (value is null)
            return default;

        // Malformed JSON in a single field must be a 400, not a 500 from an uncaught JsonException in BindAsync.
        try
        {
            return JsonSerializer.Deserialize<T>(value);
        }
        catch (JsonException)
        {
            throw MalformedValue();
        }
    }

    /// <summary>A single boolean value, or null when absent or unparseable. Kept for the model generator, which
    /// emits a call to it for a <c>bool?</c> property; no request model bound from a form carries one today.
    /// </summary>
    public static bool? Bool(StringValues values)
    {
        var value = Value(values);
        return value is not null && bool.TryParse(value, out var result) ? result : null;
    }

    /// <summary>A single request header value, or null when absent.</summary>
    public static string? Header(HttpRequest request, string name)
        => request.Headers.TryGetValue(name, out var values) && values.Count > 0 ? values.ToString() : null;

    private static StringValues Get(IFormCollection form, string name)
        => form.TryGetValue(name, out var values) ? values : StringValues.Empty;

    // Caught by Read, which names the parameter for the validation filter: the Minimal API counterpart of the MVC
    // binder recording a malformed value in the model state
    private static FormatException MalformedValue() => new("The request contains a malformed parameter value.");
}
