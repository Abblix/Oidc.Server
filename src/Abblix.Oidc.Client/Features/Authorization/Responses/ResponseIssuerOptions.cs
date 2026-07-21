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

namespace Abblix.Oidc.Client.Features.Authorization.Responses;

/// <summary>
/// The two places RFC 9207 hands the decision to local policy.
/// </summary>
public sealed class ResponseIssuerOptions
{
    /// <summary>
    /// Refuses any authorization response that names no issuer, whatever the provider advertises.
    /// </summary>
    /// <remarks>
    /// Off by default, and the default is the specification's own: section 2.4 says a client "MAY
    /// accept authorization responses that do not contain the iss parameter or reject them and
    /// exclusively support authorization servers that provide the iss parameter". Turning it on is the
    /// stronger stance and costs interoperability with every provider that has not adopted RFC 9207 -
    /// worth it for a deployment that talks to several providers, since mix-up is only a risk there
    /// (section 4: "Mix-up attacks are only relevant to clients that interact with multiple
    /// authorization servers").
    /// Note that an ID Token returned from the authorization endpoint satisfies this too, per section
    /// 4, so turning it on does not force the parameter on a hybrid or JARM flow that already names its
    /// issuer another way.
    /// </remarks>
    public bool RequireIssuer { get; set; }

    /// <summary>
    /// Refuses an <c>iss</c> parameter from a provider whose metadata does not advertise sending one,
    /// even when the value is correct.
    /// </summary>
    /// <remarks>
    /// Section 2.4 makes this a SHOULD - "Clients SHOULD discard authorization responses with the iss
    /// parameter from authorization servers that do not indicate their support for the parameter" - and
    /// then immediately explains why it is not switched on here: "However, there might be legitimate
    /// authorization servers that provide the iss parameter without indicating their support in their
    /// metadata. Local policy or configuration can determine whether to accept such responses."
    /// A provider that volunteers a correct issuer is being more careful than its metadata claims, and
    /// refusing it by default would break those deployments for no gain: the value is still compared,
    /// so an incorrect one is refused either way.
    /// </remarks>
    public bool DiscardUnadvertisedIssuer { get; set; }
}
