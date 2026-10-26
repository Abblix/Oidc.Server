// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Where the transmitter's routes were mapped: how the address of a stream's poll endpoint and of each management
/// route follows from the identity of the transmitter that answers there.
/// </summary>
/// <remarks>
/// Declared once, by the code that maps the routes, and read by <see cref="PollEndpointLocator"/> and
/// <see cref="ManagementEndpointLocator"/>, each bound to one identity. A deployment answering as one issuer has one
/// identity and one locator of each kind; a deployment answering as one issuer per tenant has a locator of each kind
/// per tenant, all derived from the routes declared here, so an address names the issuer of the transmitter that
/// minted it rather than whichever answered when the routes were mapped.
/// </remarks>
public sealed class TransmitterRoutes
{
    private Func<ITransmitterIdentity, string, Uri?>? _poll;
    private Func<ITransmitterIdentity, string, Uri>? _management;

    /// <summary>
    /// Declares where the poll endpoint is mapped, so a stream created without the host naming an address gets one
    /// that leads back to the route serving it.
    /// </summary>
    /// <remarks>
    /// Called by the code that maps the route, which happens once at startup and before any stream can be created.
    /// It is not the host's call to make: a host naming its own address uses
    /// <see cref="SharedSignalsTransmitterOptions.PollEndpointFactory"/>, which this never overrides.
    /// </remarks>
    /// <param name="pollEndpointOf">Derives, for the transmitter answering, the mapped address of a stream's poll
    /// endpoint, or answers null when this stream has none - an identifier the route cannot carry, for one. A null
    /// is a refusal a caller can act on: a create or update asking for poll delivery is answered with an error, and
    /// a declared stream is refused at startup by <see cref="ConfigurationStreamStore"/>.</param>
    /// <exception cref="InvalidOperationException">The endpoint was already mapped. A stream's poll address is
    /// stored in its configuration, so a second mapping would leave every stream created before it pointing at the
    /// first - and which streams those are depends on when each call ran.</exception>
    public void ServePollAt(Func<ITransmitterIdentity, string, Uri?> pollEndpointOf)
    {
        ArgumentNullException.ThrowIfNull(pollEndpointOf);
        if (_poll is not null)
        {
            throw new InvalidOperationException(
                "The poll endpoint is already mapped. A transmitter serves one, and the address goes "
                + "into every stream it creates.");
        }

        _poll = pollEndpointOf;
    }

    /// <summary>
    /// Declares where the management routes are mapped, so the configuration document names the addresses that
    /// lead back to them.
    /// </summary>
    /// <remarks>
    /// Called by the code that maps the routes, at startup and before any document can be served. It is not the
    /// host's call to make: a host naming its own addresses uses
    /// <see cref="SharedSignalsTransmitterOptions.ManagementEndpointFactory"/>, which this never overrides.
    /// </remarks>
    /// <param name="managementEndpointOf">Derives, for the transmitter answering, the advertised address of one
    /// management route.</param>
    /// <exception cref="InvalidOperationException">The management API was already mapped. A transmitter serves
    /// one, and a document served before a second mapping would name the first - so which addresses a receiver
    /// cached would depend on when each call ran.</exception>
    public void ServeManagementAt(Func<ITransmitterIdentity, string, Uri> managementEndpointOf)
    {
        ArgumentNullException.ThrowIfNull(managementEndpointOf);
        if (_management is not null)
        {
            throw new InvalidOperationException(
                "The Stream Management API is already mapped. A transmitter serves one, and its addresses "
                + "go into the configuration document receivers cache.");
        }

        _management = managementEndpointOf;
    }

    /// <summary>The mapped poll endpoint, or null where no route was mapped.</summary>
    internal Func<ITransmitterIdentity, string, Uri?>? Poll => _poll;

    /// <summary>The mapped management routes, or null where none were mapped.</summary>
    internal Func<ITransmitterIdentity, string, Uri>? Management => _management;
}
