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
/// because the two questions differ: a poll address varies per stream and cannot be composed, while the
/// five management routes are fixed by the specification and differ only in where they hang. Handing a
/// host five delegates to fill in would invite four of them to be right.
/// </para>
/// </remarks>
/// <param name="options">The deployment's one-time decisions, holding the host's own address if it named
/// one.</param>
public sealed class ManagementEndpointLocator(SharedSignalsTransmitterOptions options)
{
    private Func<string, Uri>? _served;

    /// <summary>
    /// Whether this transmitter offers the Stream Management API at all - what decides whether the
    /// configuration document names its five addresses.
    /// </summary>
    public bool IsOffered => options.ManagementApiBase is not null || _served is not null;

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
    /// <param name="route">The route as the specification names it, relative to wherever the API hangs.
    /// </param>
    public Uri? Of(string route)
        => options.ManagementApiBase is { } host ? new Uri(host, route) : _served?.Invoke(route);
}
