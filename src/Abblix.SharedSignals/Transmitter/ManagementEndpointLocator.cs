// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Where this transmitter serves the Stream Management API, and therefore whether its configuration
/// document names those addresses at all (SSF 1.0 Section 7.1).
/// </summary>
/// <remarks>
/// The address has the same two sources as the poll endpoint's, in the same order, and for the same
/// reason - see <see cref="PollEndpointLocator"/>.
/// <list type="bullet">
///   <item><see cref="ServedAt"/> is what the mapping declared, because only the code that maps the
///   routes knows the prefix they went on, and what it declares is the ADVERTISED prefix, so a proxy
///   that rewrites paths is covered.</item>
///   <item><see cref="SharedSignalsTransmitterOptions.ManagementEndpointFactory"/> is where a host says
///   the API is served when this deployment does not serve it - a gateway in front, or a host mapping
///   its routes through some other framework. It wins.</item>
/// </list>
/// <para>
/// A transmitter with neither source has no Stream Management API, and its document omits the five
/// members rather than naming addresses nothing answers. That is not a cosmetic difference: the document
/// is the one artifact a stranger reads without being told anything, a receiver caches it, and a
/// transmitter serving its streams from configuration has no management API by design.
/// </para>
/// <para>
/// Both sources are the same shape, and the address is composed by whoever knows where it lives rather
/// than here. An earlier draft took a BASE from the host and appended the route to it, which cost three
/// defects in as many review rounds: a base path resolved away, addresses moved to a different host by a
/// doubled separator, and a default port written into the text the document publishes. None of those can
/// reach a source that hands over the finished address, which is why the poll endpoint never had them.
/// </para>
/// </remarks>
/// <param name="options">The deployment's one-time decisions, holding the host's own source if it named
/// one.</param>
public sealed class ManagementEndpointLocator(SharedSignalsTransmitterOptions options)
{
    private Func<string, Uri>? _served;

    /// <summary>
    /// A source that hangs the management routes under one base address, for the common gateway whose
    /// five addresses differ only in their last segment.
    /// </summary>
    /// <remarks>
    /// Offered because composing an address against a base has three traps, and this library met all
    /// three while trying to do it itself. A route is rooted, so resolving it against a base REPLACES the
    /// base's path. A base whose path starts with two separators - what joining a base ending in one to
    /// <c>/ssf</c> produces - makes the reference a network-path reference, which replaces the AUTHORITY,
    /// so <c>https://gw.example//ssf</c> becomes <c>https://ssf/stream</c>. And a builder writes the port
    /// it was handed into the TEXT of what it builds, default or not, so <c>:443</c> reaches the document
    /// a receiver caches - invisible to anything comparing addresses as values, because they compare
    /// equal.
    /// <para>
    /// A host is free to write its own delegate instead; this is here so that doing the ordinary thing
    /// does not require meeting those three first.
    /// </para>
    /// </remarks>
    /// <param name="baseAddress">Where the management API hangs. Its own path is kept, and a trailing
    /// separator makes no difference.</param>
    /// <exception cref="ArgumentException">The address is relative, or carries a query or fragment -
    /// neither survives a route being appended.</exception>
    public static Func<string, Uri> Under(Uri baseAddress)
    {
        ArgumentNullException.ThrowIfNull(baseAddress);

        if (!baseAddress.IsAbsoluteUri)
        {
            throw new ArgumentException(
                "The management API base must be absolute: it is published to receivers, which hold "
                + "nothing to resolve it against.",
                nameof(baseAddress));
        }

        if (baseAddress.Query.Length > 0 || baseAddress.Fragment.Length > 0)
        {
            throw new ArgumentException(
                "The management API base carries a query or fragment, which cannot survive a route being "
                + "appended to it. Name the base alone.",
                nameof(baseAddress));
        }

        return route =>
        {
            var address = new UriBuilder(baseAddress);
            address.Path = $"{address.Path.TrimEnd('/')}/{route.TrimStart('/')}";

            // Re-parsed for the port: see the remarks above.
            return new Uri(address.Uri.AbsoluteUri);
        };
    }
    /// <summary>
    /// Declares where the management routes are mapped, so the configuration document names the
    /// addresses that lead back to them.
    /// </summary>
    /// <remarks>
    /// Called by the code that maps the routes, at startup and before any document can be served. It is
    /// not the host's call to make: a host naming its own addresses uses
    /// <see cref="SharedSignalsTransmitterOptions.ManagementEndpointFactory"/>, which this never
    /// overrides.
    /// </remarks>
    /// <param name="managementEndpointOf">Derives the advertised address of one management route.</param>
    /// <exception cref="InvalidOperationException">The management API was already mapped. A transmitter
    /// serves one, and a document served before a second mapping would name the first - so which
    /// addresses a receiver cached would depend on when each call ran.</exception>
    public void ServedAt(Func<string, Uri> managementEndpointOf)
    {
        ArgumentNullException.ThrowIfNull(managementEndpointOf);

        if (_served is not null)
        {
            throw new InvalidOperationException(
                "The Stream Management API is already mapped. A transmitter serves one, and its addresses "
                + "go into the configuration document receivers cache.");
        }

        _served = managementEndpointOf;
    }

    /// <summary>
    /// The advertised address of one management route, or null where this transmitter offers no
    /// management API.
    /// </summary>
    /// <param name="route">The route as the specification names it, relative to wherever the API hangs.
    /// </param>
    public Uri? Of(string route) => (options.ManagementEndpointFactory ?? _served)?.Invoke(route);
}
