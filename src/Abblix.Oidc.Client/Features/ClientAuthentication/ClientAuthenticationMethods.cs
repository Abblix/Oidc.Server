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


namespace Abblix.Oidc.Client.Features.ClientAuthentication;

/// <summary>
/// The ways this client can authenticate itself at the token endpoint, named as on the wire.
/// </summary>
/// <remarks>
/// Carries the same names as the server side of the family. Only the methods a base client needs are listed:
/// the ones built on a private key or a certificate belong to the paid layer that adds them.
/// </remarks>
public static class ClientAuthenticationMethods
{
    /// <summary>The secret travels in the Authorization header, as HTTP Basic.</summary>
    public const string ClientSecretBasic = "client_secret_basic";

    /// <summary>The secret travels in the request body.</summary>
    public const string ClientSecretPost = "client_secret_post";

    /// <summary>
    /// No client authentication. What a public client uses, where there is no secret to keep because the
    /// client runs somewhere the user controls.
    /// </summary>
    public const string None = "none";
}
