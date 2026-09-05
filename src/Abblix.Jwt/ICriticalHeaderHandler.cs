// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// Recipient-side handler for one JWS 'crit' header extension spec (RFC 7515 §4.1.11).
/// Covers «understood AND processed»: the handler applies the extension's recipient-side
/// semantics via <see cref="HandleAsync"/>. The JOSE header parameter name the handler
/// implements is the DI key it is registered under - see
/// <see cref="ServiceCollectionExtensions.AddCriticalHeaderHandler{THandler}"/> - so name
/// and behaviour are inseparable: a name cannot be registered without a handler behind it.
/// </summary>
/// <remarks>
/// <para>
/// One method, <see cref="HandleAsync"/>, intentionally collapses «validate» and
/// «handle». Every realistic crit extension reads the header, optionally performs
/// side effects (consume a replay nonce, emit an audit event), and returns
/// success or a typed error. Splitting into validate+handle methods would tear
/// related code apart - nonce extraction, freshness check, and consumption are
/// one logical step.
/// </para>
/// <para>
/// Two realistic processing modes share this shape:
/// <list type="bullet">
///   <item>
///     <description>
///       <b>Validate-only</b> - read the header value, compare against local
///       policy, accept or reject. Pure function over the JWT. Examples:
///       RFC 8225 'ppt' (PASSporT Type), enterprise-policy headers.
///     </description>
///   </item>
///   <item>
///     <description>
///       <b>Stateful handler</b> - read the header value, mutate external state
///       (replay-cache, audit log, counters), accept or reject. Example:
///       ACME-style 'nonce' (RFC 8555 §6.5.2) consumption with atomic
///       single-use semantics.
///     </description>
///   </item>
/// </list>
/// </para>
/// <para>
/// Signature-affecting crit extensions (RFC 7797 'b64' - Unencoded Payload Option)
/// need a pre-signature hook that transforms the JWS Signing Input bytes, which
/// MUST run before signature verification. That hook is a separate sibling
/// contract on the signing pipeline (out of scope for this interface). A b64
/// implementation of THIS interface is a thin shim registered under "b64" that
/// short-circuits to success - successful signature verification already proves
/// the directive was honoured.
/// </para>
/// <para>
/// Register with
/// <see cref="ServiceCollectionExtensions.AddCriticalHeaderHandler{THandler}"/>,
/// passing the JOSE header parameter name as the DI key. One handler owns one name;
/// a handler covering a family of related names registers under each.
/// </para>
/// </remarks>
public interface ICriticalHeaderHandler
{
    /// <summary>
    /// Apply the extension's recipient-side semantics. May read the parsed
    /// token (header and payload), consult external state via DI-injected
    /// dependencies (inject <see cref="TimeProvider"/> if the extension needs
    /// the clock), perform side effects, and reject the JWS by returning a
    /// non-null <see cref="JwtValidationError"/>. Return <see langword="null"/>
    /// on success.
    /// </summary>
    /// <param name="context">Per-call inputs: the parsed token and the
    /// validation parameters in force.</param>
    /// <param name="cancellationToken">Propagates cancellation to I/O-bound
    /// handlers (replay-store lookups, audit emitters).</param>
    Task<JwtValidationError?> HandleAsync(CriticalHeaderContext context, CancellationToken cancellationToken);
}
