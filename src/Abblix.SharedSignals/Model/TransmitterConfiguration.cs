// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Abblix.SharedSignals.Model;

/// <summary>
/// The transmitter's configuration metadata (SSF 1.0 Section 7.1): what a receiver learns from
/// "/.well-known/ssf-configuration" before creating a stream - who the transmitter is, where its
/// keys and endpoints live, and which delivery methods it speaks.
/// </summary>
public sealed record TransmitterConfiguration
{
    /// <summary>
    /// The well-known segment the metadata is published under (SSF 1.0 Section 7.2). A segment
    /// to INSERT, never a suffix to append - see <see cref="WellKnownAddress"/>.
    /// </summary>
    private const string WellKnownSegment = "/.well-known/ssf-configuration";

    /// <summary>
    /// The address the metadata for <paramref name="issuer"/> is published at: the well-known
    /// segment inserted "into the Issuer between the host component and the path component, if
    /// any", with any terminating "/" of the issuer's path removed first (SSF 1.0 Sections 7.2,
    /// 7.2.1). The insertion - not a suffix - is what lets one host serve several issuers:
    /// "https://tr.example.com/issuer1" resolves to
    /// "https://tr.example.com/.well-known/ssf-configuration/issuer1".
    /// </summary>
    /// <param name="issuer">The transmitter's issuer identifier, as documented by the
    /// transmitter.</param>
    /// <exception cref="ArgumentException">
    /// The issuer is relative, carries a query or fragment (SSF 1.0 Section 7.1 defines the
    /// identifier without them), or uses a scheme other than https on a non-loopback host - the
    /// document behind this address names every endpoint and the signing keys, so its transport
    /// is part of the trust, and Section 7.2 expects the https scheme. Loopback stays permitted
    /// for local development.</exception>
    public static Uri WellKnownAddress(Uri issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);

        if (!issuer.IsAbsoluteUri)
        {
            throw new ArgumentException(
                "An issuer identifier is an absolute URL (SSF 1.0 Section 7.1).", nameof(issuer));
        }

        if (issuer.Query.Length > 0 || issuer.Fragment.Length > 0)
        {
            throw new ArgumentException(
                $"The issuer '{issuer}' carries a query or fragment component, which an issuer "
                + "identifier has no room for (SSF 1.0 Section 7.1).",
                nameof(issuer));
        }

        if (issuer.Scheme != Uri.UriSchemeHttps && !issuer.IsLoopback)
        {
            throw new ArgumentException(
                $"Refusing to derive a configuration address from '{issuer}': the document there "
                + "names every endpoint and the signing keys, so fetching it over cleartext hands "
                + "the whole trust anchor to whoever sits on the path (SSF 1.0 Section 7.2). Use "
                + "https, or a loopback address for local development.",
                nameof(issuer));
        }

        return new UriBuilder(issuer)
        {
            Path = WellKnownSegment + issuer.AbsolutePath.TrimEnd('/'),
        }.Uri;
    }

    /// <summary>
    /// The wire names of the metadata members (SSF 1.0 Section 7.1).
    /// </summary>
    public static class ParameterNames
    {
        /// <summary>The specification version the transmitter implements.</summary>
        public const string SpecVersion = "spec_version";

        /// <summary>The transmitter's issuer identifier.</summary>
        public const string Issuer = "issuer";

        /// <summary>The transmitter's JSON Web Key Set document URL.</summary>
        public const string JwksUri = "jwks_uri";

        /// <summary>The supported delivery method URIs.</summary>
        public const string DeliveryMethodsSupported = "delivery_methods_supported";

        /// <summary>The stream configuration endpoint URL.</summary>
        public const string ConfigurationEndpoint = "configuration_endpoint";

        /// <summary>The stream status endpoint URL.</summary>
        public const string StatusEndpoint = "status_endpoint";

        /// <summary>The add subject endpoint URL.</summary>
        public const string AddSubjectEndpoint = "add_subject_endpoint";

        /// <summary>The remove subject endpoint URL.</summary>
        public const string RemoveSubjectEndpoint = "remove_subject_endpoint";

        /// <summary>The verification endpoint URL.</summary>
        public const string VerificationEndpoint = "verification_endpoint";

        /// <summary>The complex-subject members a receiver must interpret.</summary>
        public const string CriticalSubjectMembers = "critical_subject_members";

        /// <summary>The supported authorization scheme descriptions.</summary>
        public const string AuthorizationSchemes = "authorization_schemes";

        /// <summary>The default subject behavior of newly created streams.</summary>
        public const string DefaultSubjects = "default_subjects";
    }

    /// <summary>
    /// The values the "spec_version" member may carry (SSF 1.0 Section 7.1): the numerical
    /// portions of the specification versions, per the working group's naming convention.
    /// </summary>
    public static class SpecVersions
    {
        /// <summary>
        /// The final Shared Signals Framework 1.0 specification.
        /// </summary>
        public const string Final = "1_0";
    }

    /// <summary>
    /// The values the "default_subjects" member may carry (SSF 1.0 Section 7.1).
    /// </summary>
    public static class DefaultSubjectBehaviors
    {
        /// <summary>
        /// Any subject appropriate for the stream is on it by default; the receiver removes and
        /// re-adds subjects through the subject endpoints.
        /// </summary>
        public const string All = "ALL";

        /// <summary>
        /// No subjects by default; only subjects the receiver adds produce events.
        /// </summary>
        public const string None = "NONE";
    }

    /// <summary>
    /// The version of the specification the transmitter implements. Absent means the transmitter
    /// is assumed to conform to the "1_0-ID1" version (SSF 1.0 Section 7.1).
    /// </summary>
    [JsonPropertyName(ParameterNames.SpecVersion)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SpecVersion { get; init; }

    /// <summary>
    /// REQUIRED. The URL, https-schemed with no query or fragment, the transmitter asserts as its
    /// issuer identifier; identical to the "iss" claim of every SET it issues
    /// (SSF 1.0 Section 7.1).
    /// </summary>
    [JsonPropertyName(ParameterNames.Issuer)]
    public required string Issuer { get; init; }

    /// <summary>
    /// The transmitter's JSON Web Key Set document with the signing keys a receiver validates
    /// signatures against; required in practice for a transmitter issuing signed JWTs, and when
    /// present the URL must use HTTP over TLS (SSF 1.0 Section 7.1).
    /// </summary>
    [JsonPropertyName(ParameterNames.JwksUri)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? JwksUri { get; init; }

    /// <summary>
    /// The delivery method URIs the transmitter supports (SSF 1.0 Section 7.1); see
    /// <see cref="Delivery.PushDeliveryMethod.MethodUri"/> and
    /// <see cref="Delivery.PollDeliveryMethod.MethodUri"/>.
    /// </summary>
    [JsonPropertyName(ParameterNames.DeliveryMethodsSupported)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? DeliveryMethodsSupported { get; init; }

    /// <summary>
    /// The URL of the stream configuration endpoint (SSF 1.0 Sections 7.1, 8.1.1).
    /// </summary>
    [JsonPropertyName(ParameterNames.ConfigurationEndpoint)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? ConfigurationEndpoint { get; init; }

    /// <summary>
    /// The URL of the stream status endpoint (SSF 1.0 Sections 7.1, 8.1.2).
    /// </summary>
    [JsonPropertyName(ParameterNames.StatusEndpoint)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? StatusEndpoint { get; init; }

    /// <summary>
    /// The URL of the add subject endpoint (SSF 1.0 Sections 7.1, 8.1.3).
    /// </summary>
    [JsonPropertyName(ParameterNames.AddSubjectEndpoint)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? AddSubjectEndpoint { get; init; }

    /// <summary>
    /// The URL of the remove subject endpoint (SSF 1.0 Sections 7.1, 8.1.3).
    /// </summary>
    [JsonPropertyName(ParameterNames.RemoveSubjectEndpoint)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? RemoveSubjectEndpoint { get; init; }

    /// <summary>
    /// The URL of the verification endpoint (SSF 1.0 Sections 7.1, 8.1.4).
    /// </summary>
    [JsonPropertyName(ParameterNames.VerificationEndpoint)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Uri? VerificationEndpoint { get; init; }

    /// <summary>
    /// Member names in a complex subject which, when present in an event's subject member, a
    /// receiver must interpret (SSF 1.0 Section 7.1).
    /// </summary>
    [JsonPropertyName(ParameterNames.CriticalSubjectMembers)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? CriticalSubjectMembers { get; init; }

    /// <summary>
    /// The supported authorization scheme descriptions (SSF 1.0 Section 7.1.1). Kept as raw JSON
    /// objects: their shape is scheme-specific, and this package stays agnostic of how a host
    /// authorizes stream management.
    /// </summary>
    [JsonPropertyName(ParameterNames.AuthorizationSchemes)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<JsonObject>? AuthorizationSchemes { get; init; }

    /// <summary>
    /// The default behavior of newly created streams: one of
    /// <see cref="DefaultSubjectBehaviors"/>, or null when the transmitter leaves the behavior
    /// unspecified (SSF 1.0 Section 7.1).
    /// </summary>
    [JsonPropertyName(ParameterNames.DefaultSubjects)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DefaultSubjects { get; init; }
}
