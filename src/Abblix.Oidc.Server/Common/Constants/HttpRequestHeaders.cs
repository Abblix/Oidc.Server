// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// This class defines HTTP header names commonly used in HTTP requests.
/// </summary>
public static class HttpRequestHeaders
{
	/// <summary>
	/// The "Authorization" header is used in HTTP requests to include authentication credentials.
	/// It is crucial for securing API endpoints and providing proof of client identity or permissions.
	/// </summary>
	public const string Authorization = "Authorization";

	/// <summary>
	/// The "DPoP" request header carries the proof JWT bound to the current request method+URI
	/// per RFC 9449 section 4.1. Present on token, userinfo, introspection, and revocation requests
	/// when the client demonstrates proof-of-possession of the access-token-binding key.
	/// </summary>
	public const string DPoP = "DPoP";

	/// <summary>
	/// The "DPoP-Nonce" response header carries the fresh nonce on a <c>use_dpop_nonce</c>
	/// challenge response per RFC 9449 section 8 / section 9. Although a response header by direction, it
	/// lives alongside the request-header constants here to keep all DPoP wire-form names in
	/// one place; consumers are response formatters writing it onto outbound responses.
	/// </summary>
	public const string DPoPNonce = "DPoP-Nonce";
}
