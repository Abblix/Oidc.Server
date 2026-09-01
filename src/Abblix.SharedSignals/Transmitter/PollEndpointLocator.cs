// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Where this transmitter serves a stream's poll queue - the "endpoint_url value is supplied by the
/// Transmitter" of SSF 1.0 Section 8.1.1.1, and therefore the one thing a stream cannot be created with
/// poll delivery without.
/// </summary>
/// <remarks>
/// The address has two possible sources and they answer different questions.
/// <list type="bullet">
///   <item><see cref="ServedAt"/> is the address the endpoint was mapped on, declared by whatever mapped
///   it. That is the only code that knows: the route and its prefix belong to the web framework adapter,
///   and a host may move either. A proxy that rewrites paths is covered here too, because what the
///   mapping declares is the ADVERTISED prefix rather than the internal one.</item>
///   <item><see cref="SharedSignalsTransmitterOptions.PollEndpointFactory"/> is the address a host names
///   itself, for a deployment the mapped one cannot describe - a separate delivery host, or a host that
///   maps no routes through this framework at all. It wins.</item>
/// </list>
/// <para>
/// Neither could be a default computed here. A guess assembled from the issuer alone would be right only
/// while the prefix is the untouched default and silently wrong afterwards - a transmitter minting and
/// STORING an address that answers 404, which a receiver meets long after the create it belongs to
/// succeeded.
/// </para>
/// <para>
/// A transmitter with neither source offers no poll delivery: the configuration document omits the
/// method and a create asking for it is refused, which is the honest answer when there is no address to
/// hand out.
/// </para>
/// </remarks>
/// <param name="options">The deployment's one-time decisions, holding the host's own address if it named
/// one.</param>
public sealed class PollEndpointLocator(SharedSignalsTransmitterOptions options)
{
    private Func<string, Uri?>? _served;

    /// <summary>
    /// Whether this transmitter offers poll delivery at all - what "delivery_methods_supported"
    /// advertises (SSF 1.0 Section 7.1) and what a create naming poll is judged against.
    /// </summary>
    public bool IsOffered => options.PollEndpointFactory is not null || _served is not null;

    /// <summary>
    /// Declares where the poll endpoint is mapped, so a stream created without the host naming an address
    /// gets one that leads back to the route serving it.
    /// </summary>
    /// <remarks>
    /// Called by the code that maps the route, which happens once at startup and before any stream can be
    /// created. It is not the host's call to make: a host naming its own address uses
    /// <see cref="SharedSignalsTransmitterOptions.PollEndpointFactory"/>, which this never overrides.
    /// </remarks>
    /// <param name="pollEndpointOf">Derives the mapped address of a stream's poll endpoint, or answers
    /// null when this stream has none - an identifier the route cannot carry, for one. A null is a
    /// refusal a caller can act on: a create or update asking for poll delivery is answered with an
    /// error, and a declared stream is refused at startup by
    /// <see cref="ConfigurationStreamStore"/>.</param>
    /// <exception cref="InvalidOperationException">The endpoint was already mapped. A stream's poll
    /// address is stored in its configuration, so a second mapping would leave every stream created
    /// before it pointing at the first - and which streams those are depends on when each call ran.
    /// </exception>
    public void ServedAt(Func<string, Uri?> pollEndpointOf)
    {
        ArgumentNullException.ThrowIfNull(pollEndpointOf);

        if (_served is not null)
        {
            throw new InvalidOperationException(
                "The poll endpoint is already mapped. A transmitter serves one, and the address goes "
                + "into every stream it creates.");
        }

        _served = pollEndpointOf;
    }

    /// <summary>
    /// The poll endpoint of a stream, or null when there is none for it.
    /// </summary>
    /// <remarks>
    /// Null has TWO causes and a caller that can act on them differently should ask
    /// <see cref="IsOffered"/> which it is: this transmitter serves no poll delivery at all, or it does
    /// and this stream still has no address - an identifier the route cannot carry, for one. Reading
    /// null as the first cause alone makes the branch written for the second look unreachable, which is
    /// why the summary above names neither.
    /// </remarks>
    /// <param name="streamId">The stream whose queue is served there.</param>
    public Uri? Of(string streamId) => (options.PollEndpointFactory ?? _served)?.Invoke(streamId);
}
