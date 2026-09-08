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
///   <item><see cref="SharedSignalsTransmitterOptions.ManagementApiBase"/> is where a host says the API
///   is served when this deployment does not serve it - a gateway in front, or a host mapping its routes
///   through some other framework. It wins.</item>
/// </list>
/// <para>
/// A transmitter with neither source has no Stream Management API, and its document omits the five
/// members rather than naming addresses nothing answers. That is not a cosmetic difference: the document
/// is the one artifact a stranger reads without being told anything, a receiver caches it, and a
/// transmitter serving its streams from configuration has no management API by design.
/// </para>
/// <para>
/// The host's source is a base address rather than the per-route delegate the poll endpoint takes,
/// because the two questions differ: a poll address varies per stream and cannot be composed, while
/// the five management routes are fixed by the specification and differ only in where they hang.
/// Handing a host five delegates to fill in would invite four of them to be right.
/// </para>
/// <para>
/// A host that names a base is TRUSTED with it, exactly as one naming a poll address is: nothing here
/// can reach a gateway to check. So a base naming somewhere nothing answers produces the same 404 as the
/// unconditional advertisement this type exists to end - the difference is that it takes a host saying so.
/// </para>
/// </remarks>

public sealed class ManagementEndpointLocator
{
    private readonly SharedSignalsTransmitterOptions _options;
    private Func<string, Uri>? _served;

    /// <param name="options">The deployment's one-time decisions, holding the host's own address if it
    /// named one.</param>
    /// <exception cref="ArgumentException">The base could not be advertised faithfully: a relative one
    /// has no path to append a route to, and a query or fragment cannot survive one being appended.
    /// </exception>
    /// <remarks>
    /// The check sits here rather than beside the registration because the registration is handed an
    /// options ARGUMENT while this type is built from whatever the container holds - and a host may have
    /// registered its own, which the registration deliberately lets win. Checking the argument would
    /// leave exactly that host ungated, and it is the one most likely to be naming a gateway.
    /// </remarks>
    public ManagementEndpointLocator(SharedSignalsTransmitterOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.ManagementApiBase is { } managementApiBase)
        {
            if (!managementApiBase.IsAbsoluteUri)
            {
                throw new ArgumentException(
                    $"{nameof(SharedSignalsTransmitterOptions.ManagementApiBase)} must be an absolute "
                    + "address: it is published to receivers, which hold nothing to resolve it against.",
                    nameof(options));
            }

            if (managementApiBase.Query.Length > 0 || managementApiBase.Fragment.Length > 0)
            {
                throw new ArgumentException(
                    $"{nameof(SharedSignalsTransmitterOptions.ManagementApiBase)} carries a query or "
                    + "fragment, which cannot survive a route being appended to it. Name the base alone.",
                    nameof(options));
            }
        }

        _options = options;
    }

    /// <summary>
    /// Declares where the management routes are mapped, so the configuration document names the
    /// addresses that lead back to them.
    /// </summary>
    /// <remarks>
    /// Called by the code that maps the routes, at startup and before any document can be served. It is
    /// not the host's call to make: a host naming its own address uses
    /// <see cref="SharedSignalsTransmitterOptions.ManagementApiBase"/>, which this never overrides.
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
    /// <remarks>
    /// Built from the base's own parts rather than by resolving the route against it, because reference
    /// resolution throws the base away in three of the four spellings a host can write, and one of those
    /// takes the HOST with it. A rooted reference replaces the whole path. A relative one drops the
    /// base's last segment unless the base ends in a separator, that segment reading as a file rather
    /// than a directory. And a path beginning with two separators - what a host gets by joining a base
    /// that already ends in one to <c>/ssf</c> - makes the reference a network-path reference, which
    /// replaces the AUTHORITY: <c>https://gw.example//ssf</c> would advertise <c>https://ssf/stream</c>.
    /// <para>
    /// Joining the parts makes the SPELLING of both sides stop mattering - a leading separator on the
    /// route, a trailing one on the base - so there is no spelling rule for a caller to remember. What the
    /// base may CARRY is a different question and is not free: it has to be absolute and hold no query or
    /// fragment, refused by this type's constructor, because neither of those survives a path being
    /// appended.
    /// </para>
    /// </remarks>
    /// <param name="route">The route as the specification names it, relative to wherever the API hangs.
    /// </param>
    public Uri? Of(string route)
    {
        if (_options.ManagementApiBase is not { } host)
        {
            return _served?.Invoke(route);
        }

        var address = new UriBuilder(host);
        address.Path = $"{address.Path.TrimEnd('/')}/{route.TrimStart('/')}";

        // Re-parsed, because UriBuilder keeps the port it was given in the TEXT of the address it
        // builds, default or not - and that text is what the document publishes, so a base naming no
        // port would be advertised with ":443" on every one of the five members. The two forms compare
        // EQUAL as Uri, so nothing asserting on Uri can see the difference; only the published string
        // can. An explicit non-default port survives the round trip.
        return new Uri(address.Uri.AbsoluteUri);
    }
}
