// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

/// <summary>
/// Configuration options for secure HTTP fetching with SSRF protection.
/// </summary>
public class SecureHttpFetchOptions
{
    /// <summary>
    /// Maximum time to wait for the complete HTTP request (including DNS resolution and data transfer).
    /// Default: 30 seconds.
    /// </summary>
    /// <remarks>
    /// This timeout applies to the entire request lifecycle. Lower values provide better protection
    /// against slowloris attacks but may cause failures for legitimate slow responses.
    /// </remarks>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Maximum allowed response size in bytes.
    /// Default: 5 MB (5242880 bytes).
    /// </summary>
    /// <remarks>
    /// This limit prevents denial-of-service attacks via extremely large responses.
    /// Increase this value if you need to fetch larger documents (e.g., large JSON Web Key Sets).
    /// </remarks>
    public long MaxResponseSizeBytes { get; set; } = 5 << 20;

    /// <summary>
    /// How long a client's fetched key set is held before it is fetched again. Default: 1 hour.
    /// </summary>
    /// <remarks>
    /// These keys verify request objects and client assertions, so this bounds how long a key the client has
    /// already removed from its published set is still accepted here.
    /// </remarks>
    public TimeSpan ClientKeysCacheDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How long a protected resource's fetched key set is held before it is fetched again. Default: 1 hour.
    /// </summary>
    /// <remarks>
    /// This one sits on the hottest path of the four: the key is read while issuing an access token for that
    /// resource, so every issuance would otherwise be an HTTP request. Lowering it buys faster propagation of
    /// a rotated resource key at the cost of a fetch per interval.
    /// </remarks>
    public TimeSpan ResourceKeysCacheDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How long a software-statement issuer's fetched key set is held before it is fetched again.
    /// Default: 1 hour.
    /// </summary>
    /// <remarks>
    /// Read only while a dynamic client registration presents a software statement, so the coldest of the
    /// four.
    /// </remarks>
    public TimeSpan SoftwareStatementKeysCacheDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// List of allowed URI schemes, or null when the host does not state them and the HTTPS-only
    /// default in <see cref="EffectiveAllowedSchemes"/> applies.
    /// </summary>
    /// <remarks>
    /// Null and empty mean different things. Null is "not stated", and the default applies. An empty
    /// list is stated: it lifts the scheme restriction entirely, and it is the one way a
    /// configuration file can say so, since null has no spelling there.
    ///
    /// Null rather than a defaulted value on purpose. The .NET configuration binder adds to a
    /// collection a property already holds instead of replacing it, so a default stored here would
    /// arrive on top of what the file lists - a host that configures plain HTTP would silently keep
    /// HTTPS allowed beside it, on the allowlist SSRF validation consumes.
    /// Read <see cref="EffectiveAllowedSchemes"/> to decide anything.
    /// </remarks>
    public string[]? AllowedSchemes { get; set; }

    /// <summary>
    /// The schemes a fetched URI may use: what the host states, or HTTPS alone when it states
    /// nothing. A host that states an empty list gets an empty list, which the validator reads as
    /// no scheme restriction. Computed from <see cref="AllowedSchemes"/> and not bindable: a
    /// configuration key of this name is silently ignored, so the file always writes
    /// <see cref="AllowedSchemes"/>.
    /// </summary>
    public string[] EffectiveAllowedSchemes => AllowedSchemes ?? HttpsOnly;

    private static readonly string[] HttpsOnly = [Uri.UriSchemeHttps];

    /// <summary>
    /// Whether to block requests to private networks.
    /// Default: true.
    /// </summary>
    /// <remarks>
    /// When true, blocks requests to:
    /// - Private IP ranges (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    /// - Link-local addresses (169.254.0.0/16 for IPv4, fe80::/10 for IPv6)
    /// - Loopback addresses (127.0.0.0/8 for IPv4, ::1 for IPv6)
    /// - Common internal hostnames (localhost, internal, etc.)
    /// Set to false only in development environments where fetching from internal networks is required.
    /// </remarks>
    public bool BlockPrivateNetworks { get; set; } = true;

    /// <summary>
    /// Destinations this server may reach whatever the rules above say. Default: null, meaning none.
    /// </summary>
    /// <remarks>
    /// This is how a deployment reaches one known service inside its own network without standing the
    /// protection down. The rules above are a blanket refusal that cannot be narrowed, only switched off, so
    /// an authorization server that must call a sibling in its own cluster would otherwise set
    /// <see cref="BlockPrivateNetworks"/> to <c>false</c> and restate <see cref="AllowedSchemes"/> in full,
    /// HTTPS included - and both
    /// relaxations apply equally to every address a *client* supplies: a key set, a sector identifier, a
    /// back-channel logout endpoint. Naming the one destination leaves the refusal total everywhere else.
    /// <para>
    /// An entry is matched on scheme, host and port, and additionally on path when it carries one. So
    /// <c>http://localhost:5002</c> permits every path on that origin, while
    /// <c>http://localhost:5002/manage/api/signout-backchannel-oidc</c> permits that one and leaves the rest
    /// of the host refused. Prefer the second: this permission is read at client registration as well as on
    /// the way out, and registration is where a client chooses the address.
    /// </para>
    /// An entry carrying a query, a fragment or user information is refused at startup rather than ignored,
    /// because an entry permitting more than it appears to say is the failure this option exists to avoid.
    /// </remarks>
    public Uri[]? AllowedDestinations { get; set; }
}
