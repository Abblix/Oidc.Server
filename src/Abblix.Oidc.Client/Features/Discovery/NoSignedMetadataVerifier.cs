// Abblix OIDC Client Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
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

using System.Text.Json.Nodes;

namespace Abblix.Oidc.Client.Features.Discovery;

/// <summary>
/// Acts on the document as published, ignoring any <c>signed_metadata</c> it carries.
/// </summary>
/// <remarks>
/// This is the default, and it is a statement about where the assurance comes from rather than an omission.
/// The document is read over TLS from the address derived from the issuer identifier, and RFC 8414
/// section 6.2 names that check - the server certificate being valid for the issuer identifier URL - as what
/// "prevents man-in-middle and DNS-based attacks". A signature verified with keys named by the same document
/// would add nothing to it: whoever could forge the document could also name the key that vouches for it.
///
/// The signature earns its keep only against keys the host holds independently of the document, which is
/// what <c>AddSignedMetadataVerification</c> arranges. Until a host does that, this client does not support
/// signed metadata in the sense RFC 8414 section 2.1 uses the word, and so the precedence rule that section
/// states does not apply to it.
/// </remarks>
public sealed class NoSignedMetadataVerifier : ISignedMetadataVerifier
{
    /// <inheritdoc />
    public Task<JsonObject> ApplyAsync(JsonObject document, CancellationToken cancellationToken = default)
        => Task.FromResult(document);
}
