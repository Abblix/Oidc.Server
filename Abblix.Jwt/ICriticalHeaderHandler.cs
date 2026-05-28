// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
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

namespace Abblix.Jwt;

/// <summary>
/// Recipient-side handler for one JWS 'crit' header extension spec (RFC 7515 §4.1.11).
/// Covers «understood AND processed»: the implementation declares which JOSE header
/// parameter name(s) the extension introduces via <see cref="UnderstoodNames"/>, and
/// applies the extension's recipient-side semantics via <see cref="HandleAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// One method, <see cref="HandleAsync"/>, intentionally collapses «validate» and
/// «handle». Every realistic crit extension reads the header, optionally performs
/// side effects (consume a replay nonce, emit an audit event), and returns
/// success or a typed error. Splitting into validate+handle methods would tear
/// related code apart — nonce extraction, freshness check, and consumption are
/// one logical step.
/// </para>
/// <para>
/// Two realistic processing modes share this shape:
/// <list type="bullet">
///   <item>
///     <description>
///       <b>Validate-only</b> — read the header value, compare against local
///       policy, accept or reject. Pure function over the JWT. Examples:
///       RFC 8225 'ppt' (PASSporT Type), enterprise-policy headers.
///     </description>
///   </item>
///   <item>
///     <description>
///       <b>Stateful handler</b> — read the header value, mutate external state
///       (replay-cache, audit log, counters), accept or reject. Example:
///       ACME-style 'nonce' (RFC 8555 §6.5.2) consumption with atomic
///       single-use semantics.
///     </description>
///   </item>
/// </list>
/// </para>
/// <para>
/// Signature-affecting crit extensions (RFC 7797 'b64' — Unencoded Payload Option)
/// need a pre-signature hook that transforms the JWS Signing Input bytes, which
/// MUST run before signature verification. That hook is a separate sibling
/// contract on the signing pipeline (out of scope for this interface). A b64
/// implementation of THIS interface is a thin shim that declares understanding
/// of "b64" and short-circuits to success — successful signature verification
/// already proves the directive was honoured.
/// </para>
/// <para>
/// Register with
/// <see cref="ServiceCollectionExtensions.AddCriticalHeaderHandler{THandler}"/>.
/// Two handlers claiming the same name fail loud at validator construction —
/// each crit name MUST have exactly one handler.
/// </para>
/// </remarks>
public interface ICriticalHeaderHandler
{
    /// <summary>
    /// JOSE header parameter names this handler implements. Byte-exact match
    /// per RFC 7515 §5.3. MUST be non-empty. Multi-name is allowed for specs
    /// that introduce a family of related parameters (rare); most extensions
    /// declare a single name.
    /// </summary>
    IReadOnlySet<string> UnderstoodNames { get; }

    /// <summary>
    /// Apply the extension's recipient-side semantics. May read the parsed
    /// token (header and payload), consult external state via the context's
    /// time provider or DI-injected dependencies, perform side effects, and
    /// reject the JWS by returning a non-null <see cref="JwtValidationError"/>.
    /// Return <see langword="null"/> on success.
    /// </summary>
    /// <param name="context">Per-call inputs (parsed token, validation
    /// parameters, time provider, cancellation token).</param>
    Task<JwtValidationError?> HandleAsync(CriticalHeaderContext context);
}
