// Abblix OIDC Server Library
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

namespace Abblix.Oidc.Server.Features.RichAuthorizationRequests;

/// <summary>
/// Host-renderable description of a single RFC 9396 <c>authorization_details</c> entry, produced
/// by <see cref="IAuthorizationDetailValidator.BuildConsentDescriptorAsync"/>. Surfaces a structured,
/// localisable shape the consent UI can render directly -- without the host having to inspect the
/// per-type JSON payload itself. Validators that do not override the default implementation return
/// <c>null</c>, and the host is expected to fall back to a raw JSON dump.
/// </summary>
/// <param name="Title">Short heading naming the operation (e.g. "Payment transfer", "Account
/// information access"). One short phrase, no end punctuation.</param>
/// <param name="Summary">One-sentence human-readable summary of what consenting to this entry
/// authorises (e.g. "Transfer 500 EUR to IBAN DE02 100100100123456789"). The consent UI typically
/// shows this directly under the title.</param>
/// <param name="Details">Optional structured key/value pairs the UI can render as a labelled list
/// (e.g. {"Currency": "EUR", "Amount": "500.00", "Beneficiary IBAN": "DE02..."}). Order is preserved
/// by the caller; keys are display-side labels and may be localisable by the host before they reach
/// this record. <c>null</c> when the entry has no field-level breakdown worth showing.</param>
public record AuthorizationDetailDescriptor(
    string Title,
    string Summary,
    IReadOnlyList<KeyValuePair<string, string>>? Details = null);
