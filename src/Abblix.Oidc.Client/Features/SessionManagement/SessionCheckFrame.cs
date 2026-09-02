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

namespace Abblix.Oidc.Client.Features.SessionManagement;

/// <summary>
/// The page this application serves as its session-watching frame, and the policy that page needs.
/// </summary>
/// <param name="Html">The document to serve.</param>
/// <param name="ContentSecurityPolicy">
/// The policy to serve it under. It names the nonce the document's own script carries, so the two are
/// produced together and neither is usable without the other.
/// </param>
public sealed record SessionCheckFrame(string Html, string ContentSecurityPolicy);
