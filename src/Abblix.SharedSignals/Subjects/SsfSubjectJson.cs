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

using System.Text.Json;
using Abblix.SecurityEvents.Subjects;

namespace Abblix.SharedSignals.Subjects;

/// <summary>
/// The serializer options SSF documents carrying Subject Identifiers are read with: the RFC 9493
/// dispatch extended with <see cref="SsfSubjectFormats.Registrations"/>. One shared instance,
/// because both roles need the same vocabulary - a receiver reading "sub_id" off a SET and a
/// transmitter reading a subject request body.
/// </summary>
public static class SsfSubjectJson
{
    /// <summary>
    /// The shared options, frozen so no consumer can quietly widen or narrow the vocabulary for
    /// everyone else; a deployment adding proprietary formats builds its own options instead.
    /// </summary>
    public static JsonSerializerOptions Options { get; } = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            Converters = { new SubjectIdentifierJsonConverter(SsfSubjectFormats.Registrations) },
        };

        // Freezing demands a resolver be already chosen; populating the default reflection one
        // here keeps the shared instance both usable and immutable.
        options.MakeReadOnly(populateMissingResolver: true);
        return options;
    }
}
