// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

namespace Abblix.Jwt;

/// <summary>
/// Provides constants for various JWT and OpenID Connect claim types.
/// Includes both registered claim types and public claim types as defined in various standards.
/// This classification helps in ensuring interoperability across different systems and services
/// by adhering to a common set of identifiers for claims.
/// </summary>
public static class IanaClaimTypes
{
    /// <summary>
    /// A set of predefined claims recommended for ensuring interoperability among different systems.
    /// These claims are widely recognized and provide basic information necessary
    /// for many authentication and authorization processes.
    /// </summary>
    public static IReadOnlyCollection<string> Registered = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        Iss, Sub, Aud, Exp, Nbf, Iat, Jti
    };

    /// <summary>
    /// A set of public claims that can be defined by applications as needed.
    /// To ensure global uniqueness and avoid collisions, these claims should either be registered
    /// with the IANA JSON Web Token Registry or be defined within a namespace that is resistant to collisions,
    /// such as a URI.
    /// </summary>
    public static IReadOnlyCollection<string> Public = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        Name, GivenName, FamilyName, MiddleName, Nickname, PreferredUsername, Profile, Picture, Website, Email,
        EmailVerified, Gender, Birthdate, Zoneinfo, Locale, PhoneNumber, PhoneNumberVerified, Address, UpdatedAt, Azp,
        Nonce, AuthTime, AtHash, CHash, Acr, Amr, SubJwk, Cnf, SipFromTag, SipDate, SipCallid, SipCseqNum, SipViaBranch,
        Orig, Dest, Mky, Events, Toe, Txn, Rph, Sid, Vot, Vtm, Attest, Origid, Act, Scope, ClientId, MayAct, Jcard,
        AtUseNbr, Div, Opt, Vc, Vp, Sph, AceProfile, Cnonce, Exi, Roles, Groups, Entitlements, TokenIntrospection,
        Cdniv, Cdnicrit, Cdniip, Cdniuc, Cdniets, Cdnistt, Cdnistd, SigValClaims, AuthorizationDetails
    };

    #region RFC7519, Section 4.1.1 - Issuer Claim

    /// <summary>
    /// Represents the principal (e.g., authorization server) that issued the JWT.
    /// </summary>
    /// <remarks>
    /// Defined in RFC 7519, Section 4.1.1. It is a case-sensitive string containing a StringOrURI value.
    /// Use this claim to identify the issuer of the JWT uniquely.
    /// </remarks>
    public const string Iss = "iss";

    #endregion

    #region RFC7519, Section 4.1.2 - Subject Claim

    /// <summary>
    /// Represents the principal that is the subject of the JWT.
    /// </summary>
    /// <remarks>
    /// Defined in RFC 7519, Section 4.1.2. The "sub" value is a case-sensitive string containing a StringOrURI value.
    /// This claim is used to identify the subject of the JWT, which could be an end user or a device.
    /// </remarks>
    public const string Sub = "sub";

    #endregion

    #region RFC7519, Section 4.1.3 - Audience Claim

    /// <summary>
    /// Identifies the recipients that the JWT is intended for.
    /// </summary>
    /// <remarks>
    /// Defined in RFC 7519, Section 4.1.3. It is generally a case-sensitive string or an array of strings containing StringOrURI values.
    /// The audience claim ensures that the JWT is sent to the intended recipients.
    /// </remarks>
    public const string Aud = "aud";

    #endregion

    #region RFC7519, Section 4.1.4 - Expiration Time Claim

    /// <summary>
    /// Specifies the expiration time on or after which the JWT must not be accepted for processing.
    /// </summary>
    /// <remarks>
    /// Defined in RFC 7519, Section 4.1.4. The "exp" claim is a NumericDate value. Use this claim to define the validity period of the JWT.
    /// </remarks>
    public const string Exp = "exp";

    #endregion

    #region RFC7519, Section 4.1.5 - Not Before Claim

    /// <summary>
    /// Defines a time before which the JWT MUST NOT be accepted for processing.
    /// </summary>
    /// <remarks>
    /// Defined in RFC 7519, Section 4.1.5. The "nbf" (Not Before) claim is a NumericDate value.
    /// This claim helps in ensuring that a JWT is not accepted before a certain time.
    /// </remarks>
    public const string Nbf = "nbf";

    #endregion

    #region RFC7519, Section 4.1.6 - Issued At Claim

    /// <summary>
    /// Indicates the time at which the JWT was issued.
    /// </summary>
    /// <remarks>
    /// Defined in RFC 7519, Section 4.1.6. The "iat" (Issued At) claim is a NumericDate value.
    /// This claim can be used to determine the age of the JWT.
    /// </remarks>
    public const string Iat = "iat";

    #endregion

    #region RFC7519, Section 4.1.7 - JWT ID Claim

    /// <summary>
    /// Provides a unique identifier for the JWT.
    /// </summary>
    /// <remarks>
    /// Defined in RFC 7519, Section 4.1.7. The "jti" (JWT ID) claim is a case-sensitive string.
    /// Use this claim to prevent the JWT from being replayed.
    /// </remarks>
    public const string Jti = "jti";

    #endregion

    #region OpenID Connect Core 1.0, Section 5.1 - Personal Identifiable Information Claims

    /// <summary>
    /// Represents the full name of the user.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect for representing the user's full name in a single string. It might include the first, middle, last, and other names.
    /// </remarks>
    public const string Name = "name";

    /// <summary>
    /// Represents the first or given name(s) of the user.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim is intended to refer to the user's first name or given name(s). It allows for middle names if applicable.
    /// </remarks>
    public const string GivenName = "given_name";

    /// <summary>
    /// Represents the surname(s) or last name(s) of the user.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim focuses on the user's family name or surname(s), excluding middle names.
    /// </remarks>
    public const string FamilyName = "family_name";

    /// <summary>
    /// Represents the middle name(s) of the user.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim is intended for the user's middle name(s), which might not be present for all users.
    /// </remarks>
    public const string MiddleName = "middle_name";

    /// <summary>
    /// Represents the casual name of the user.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim is for the user's casual or informal name that might differ from their legal name.
    /// </remarks>
    public const string Nickname = "nickname";

    /// <summary>
    /// The username preferred by the user, which may be different from their actual or legal name.
    /// </summary>
    /// <remarks>
    /// This claim is used to convey the user's preferred username within the system. It allows the user
    /// to specify a nickname or alias that is used within the application for display purposes,
    /// providing a more personalized user experience.
    /// </remarks>
    public const string PreferredUsername = "preferred_username";

    /// <summary>
    /// Represents the URL of the user's profile page.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. It is the URL of a web page containing information about the user or a social profile page.
    /// </remarks>
    public const string Profile = "profile";

    /// <summary>
    /// Represents the URL of the user's profile picture.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim provides a URL pointing to a profile picture or avatar of the user.
    /// </remarks>
    public const string Picture = "picture";

    /// <summary>
    /// Represents the URL of the user's web page or blog.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim indicates the URL of the user's personal or business website.
    /// </remarks>
    public const string Website = "website";

    /// <summary>
    /// Represents the user's preferred email address.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim is for the user's preferred email. Note that this email address might not be unique.
    /// </remarks>
    public const string Email = "email";

    /// <summary>
    /// Represents whether the user's email address has been verified.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect as a boolean. True if the user's email address has been verified; otherwise false.
    /// </remarks>
    public const string EmailVerified = "email_verified";

    /// <summary>
    /// Represents the user's gender.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim can be used to convey the user's gender. The value is not strictly defined and can vary based on the user's preference and the application's requirements.
    /// </remarks>
    public const string Gender = "gender";

    /// <summary>
    /// Represents the user's date of birth.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim is for the user's birthdate, typically represented in the ISO 8601:2004 YYYY-MM-DD format.
    /// </remarks>
    public const string Birthdate = "birthdate";

    /// <summary>
    /// Represents the user's time zone.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim indicates the user's time zone, facilitating localization and personalization.
    /// </remarks>
    public const string Zoneinfo = "zoneinfo";

    /// <summary>
    /// Represents the user's locale.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim specifies the user's preferred language and optionally, region. Typically represented as a language tag, e.g., en-US or fr-CA.
    /// </remarks>
    public const string Locale = "locale";

    /// <summary>
    /// Represents the user's phone number.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim provides the user's preferred phone number. The format of the number can vary and it's not guaranteed to be in a standard format.
    /// </remarks>
    public const string PhoneNumber = "phone_number";

    /// <summary>
    /// Indicates whether the user's phone number has been verified.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect as a boolean. True if the user's phone number has been verified; otherwise false.
    /// </remarks>
    public const string PhoneNumberVerified = "phone_number_verified";

    /// <summary>
    /// Represents the user's postal address.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This JSON structured claim contains components of the user's address such as street address, locality, region, postal code, and country.
    /// </remarks>
    public const string Address = "address";

    /// <summary>
    /// Indicates when the user's information was last updated.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim provides a Unix time stamp indicating when the user's information was last updated.
    /// </remarks>
    public const string UpdatedAt = "updated_at";

    #endregion

    #region OpenID Connect Core 1.0, Section 2 - Other Claims

    /// <summary>
    /// Represents the authorized party - the party to which the ID Token was issued.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim is particularly useful in delegated scenarios to identify the party using the ID Token.
    /// </remarks>
    public const string Azp = "azp";

    /// <summary>
    /// A string value used to associate a client session with an ID Token.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect to mitigate replay attacks by binding a session to a token.
    /// </remarks>
    public const string Nonce = "nonce";

    /// <summary>
    /// Indicates the time when the authentication occurred.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim is critical in scenarios where the application requires assurance about
    /// the moment of authentication, such as re-authentication or step-up authentication.
    /// </remarks>
    public const string AuthTime = "auth_time";

    /// <summary>
    /// Represents the hash of the access token issued.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim is included in the ID Token and is a hash of the access token,
    /// allowing the recipient to validate the integrity of the access token. It is particularly useful
    /// in implicit and authorization code flows.
    /// </remarks>
    public const string AtHash = "at_hash";

    /// <summary>
    /// Represents the Authentication Context Class Reference.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim specifies the authentication context class that the authentication
    /// performed satisfied. It allows clients to request and services to assert the strength of an authentication process.
    /// </remarks>
    public const string Acr = "acr";

    /// <summary>
    /// Represents the Authentication Methods References.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim is used to specify the authentication methods used in the authentication process.
    /// It provides transparency about how the authentication was performed, such as 'pwd' for password-based
    /// or 'mfa' for multi-factor authentication.
    /// </remarks>
    public const string Amr = "amr";

    #endregion

    #region OpenID Connect Core 1.0, Section 3.3.2.11

    /// <summary>
    /// Represents the Code Hash Value.
    /// </summary>
    /// <remarks>
    /// Used in OpenID Connect. This claim is used in the ID Token to provide a hash of the authorization code.
    /// It ensures that the authorization code is bound to the ID Token, enhancing the security of the code exchange process.
    /// </remarks>
    public const string CHash = "c_hash";

    #endregion

    #region OpenID Connect Core 1.0, Section 7.4

    /// <summary>
    /// Represents the subject's public key as a JSON Web Key (JWK).
    /// </summary>
    /// <remarks>
    /// Used in scenarios where public keys are associated with JWT subjects.
    /// This claim allows embedding a public key directly within a JWT, facilitating key discovery and distribution.
    /// </remarks>
    public const string SubJwk = "sub_jwk";

    #endregion

    #region RFC7800, Section 3.1

    /// <summary>
    /// Represents confirmation methods used by the token.
    /// </summary>
    /// <remarks>
    /// Utilized in scenarios that require additional confirmation of token validity, such as DPoP
    /// (Demonstrating Proof of Possession). This claim helps in binding tokens to specific cryptographic keys.
    /// </remarks>
    public const string Cnf = "cnf";

    #endregion

    #region RFC8055 - SIP Claims

    /// <summary>
    /// "sip_from_tag" - Value from the SIP 'From' tag header field, used in SIP-based communications.
    /// </summary>
    public const string SipFromTag = "sip_from_tag";

    /// <summary>
    /// "sip_date" - Value from the SIP 'Date' header field, indicating the time of the SIP message.
    /// </summary>
    public const string SipDate = "sip_date";

    /// <summary>
    /// "sip_callid" - Value from the SIP 'Call-Id' header field, uniquely identifying the SIP call.
    /// </summary>
    public const string SipCallid = "sip_callid";

    /// <summary>
    /// "sip_cseq_num" - Numeric value from the SIP 'CSeq' header field, indicating the command sequence number in SIP protocol.
    /// </summary>
    public const string SipCseqNum = "sip_cseq_num";

    /// <summary>
    /// "sip_via_branch" - Value from the SIP 'Via' branch parameter, used in routing SIP messages.
    /// </summary>
    public const string SipViaBranch = "sip_via_branch";

    #endregion

    #region RFC8225, Section 5.2.1 - 5.2.2

    /// <summary>
    /// Represents the originating identity in telecommunication protocols.
    /// </summary>
    /// <remarks>
    /// It's used to convey the identity of the originator in communication protocols, aiding in the identification
    /// and verification of the call origin for security and billing purposes.
    /// </remarks>
    public const string Orig = "orig";

    /// <summary>
    /// Represents the destination identity in telecommunication protocols.
    /// </summary>
    /// <remarks>
    /// Useful in communication protocols to convey the intended recipient or destination of the communication,
    /// supporting routing, billing, and security measures.
    /// </remarks>
    public const string Dest = "dest";

    /// <summary>
    /// Represents a media key fingerprint.
    /// </summary>
    /// <remarks>
    /// Used in secure communication protocols to provide a fingerprint of the cryptographic key used for
    /// encrypting media, enhancing the security of media exchanges by facilitating key verification.
    /// </remarks>
    public const string Mky = "mky";

    #endregion

    #region RFC8417, Section 2.2 - Security Event Tokens

    /// <summary>
    /// Represents specific security events or state changes.
    /// </summary>
    /// <remarks>
    /// Used in Security Event Tokens (SETs) to convey information about security-related events or changes,
    /// such as authentication events or configuration changes, aiding in security monitoring and response.
    /// </remarks>
    public const string Events = "events";

    /// <summary>
    /// Represents the time of the security event.
    /// </summary>
    /// <remarks>
    /// This claim is used in Security Event Tokens (SETs) to indicate the precise time at which the described
    /// security event occurred, facilitating accurate incident tracking and response.
    /// </remarks>
    public const string Toe = "toe";

    /// <summary>
    /// Represents a transaction identifier.
    /// </summary>
    /// <remarks>
    /// Often utilized in financial transactions and other scenarios where tracking the identity and state
    /// of individual transactions is critical for security, auditing, and reconciliation processes.
    /// </remarks>
    public const string Txn = "txn";

    #endregion

    #region RFC8443, Section 3 - Resource Priority

    /// <summary>
    /// Represents a resource priority header.
    /// </summary>
    /// <remarks>
    /// This claim is used to indicate the priority of a resource or process in network communications,
    /// ensuring that critical resources receive appropriate handling and prioritization in congested or
    /// limited-capacity environments.
    /// </remarks>
    public const string Rph = "rph";

    #endregion

    #region OpenID Connect Front-Channel Logout 1.0, Section 3

    /// <summary>
    /// Represents the session ID for front-channel logout in OpenID Connect sessions.
    /// </summary>
    /// <remarks>
    /// This claim is critical for implementing front-channel logout mechanisms, allowing clients and servers
    /// to coordinate user sessions and logout processes across multiple applications and services.
    /// </remarks>
    public const string Sid = "sid";

    #endregion

    #region rfc8485 - Vector of Trust

    /// <summary>
    /// Represents the vector of trust for authentication processes.
    /// </summary>
    /// <remarks>
    /// Used to convey the level of confidence in the authentication process, detailing the methods used and
    /// their security properties. This claim is particularly useful in contexts requiring a nuanced understanding
    /// of authentication assurance.
    /// </remarks>
    public const string Vot = "vot";

    /// <summary>
    /// Represents the vector of trust trustmark.
    /// </summary>
    /// <remarks>
    /// Provides a URL to a trustmark that further describes the trust vector associated with the authentication process,
    /// offering a means to verify the authentication methods and their adherence to certain standards or practices.
    /// </remarks>
    public const string Vtm = "vtm";

    #endregion

    #region rfc8588 - SHAKEN Framework

    /// <summary>
    /// Represents the attestation level in SHAKEN/STIR frameworks.
    /// </summary>
    /// <remarks>
    /// This claim is used within the SHAKEN/STIR framework for telecommunication services, indicating the level
    /// of attestation for the origin of a call, which aids in combating caller ID spoofing and fraud.
    /// </remarks>
    public const string Attest = "attest";

    /// <summary>
    /// Represents the originating identifier in the SHAKEN framework.
    /// </summary>
    /// <remarks>
    /// Used to uniquely identify the originator of a call within the SHAKEN framework, facilitating traceability
    /// and verification of the call's origin, and enhancing trust in telecommunication ecosystems.
    /// </remarks>
    public const string Origid = "origid";

    #endregion

    #region RFC8693 - OAuth 2.0 Token Exchange

    /// <summary>
    /// Represents the actor in OAuth 2.0 token exchange.
    /// </summary>
    /// <remarks>
    /// This claim is used to indicate the party that the token represents, especially in delegation and
    /// impersonation scenarios, allowing APIs and services to verify the actual party making a request.
    /// </remarks>
    public const string Act = "act";

    /// <summary>
    /// Represents the scope associated with an access token.
    /// </summary>
    /// <remarks>
    /// Specifies the permissions or access rights granted to an access token, defining what actions
    /// the token bearer is authorized to perform. This claim is fundamental in controlling access to resources.
    /// </remarks>
    public const string Scope = "scope";

    /// <summary>
    /// Represents the client identifier in OAuth 2.0 contexts.
    /// </summary>
    /// <remarks>
    /// Identifies the OAuth 2.0 client that requested the token, providing a mechanism for associating a token
    /// with a specific registered client application, critical for enforcing client-specific access policies.
    /// </remarks>
    public const string ClientId = "client_id";

    /// <summary>
    /// Indicates the parties that the token bearer is authorized to act on behalf of.
    /// </summary>
    /// <remarks>
    /// This claim is used in scenarios where a token bearer is permitted to act on behalf of other parties,
    /// enabling delegation of rights and facilitating advanced authorization scenarios.
    /// </remarks>
    public const string MayAct = "may_act";

    #endregion

    #region rfc8688 - jCard Data

    /// <summary>
    /// Contains jCard data, representing contact information in a JSON format.
    /// </summary>
    /// <remarks>
    /// This claim is used to convey contact information in a structured format that mirrors the vCard specification,
    /// facilitating interoperable exchange of personal or organizational contact details.
    /// </remarks>
    public const string Jcard = "jcard";

    #endregion

    #region ETSI GS NFV-SEC 022 - API Request Number

    /// <summary>
    /// Indicates the number of API requests for which the access token can be used.
    /// </summary>
    /// <remarks>
    /// This claim is used primarily in environments where token usage is tightly controlled and monitored,
    /// providing a mechanism for limiting the number of requests a token can authorize to enhance security and
    /// manage resource utilization.
    /// </remarks>
    public const string AtUseNbr = "at_use_nbr";

    #endregion

    #region rfc8946 - Diverted Call Information


    /// <summary>
    /// Contains information about a call that was diverted from its original destination.
    /// </summary>
    /// <remarks>
    /// This claim is used in telecommunications contexts to provide details about call diversions,
    /// aiding in the management and tracing of call flows and in the implementation of services that
    /// react to call redirection.
    /// </remarks>
    public const string Div = "div";

    /// <summary>
    /// Contains the original PASSporT in full form, often used in call diversion scenarios.
    /// </summary>
    /// <remarks>
    /// This claim is utilized in telecommunications to verify the authenticity of redirected calls by providing
    /// a cryptographic assertion of the call's origin, enhancing trust and security in voice communications.
    /// </remarks>
    public const string Opt = "opt";

    #endregion

    #region W3C Verifiable Credentials

    /// <summary>
    /// Represents a verifiable credential as specified in the W3C Recommendation.
    /// </summary>
    /// <remarks>
    /// This claim is used to convey credentials that can be cryptographically verified, supporting a wide range
    /// of applications from identity verification to qualification attestation in a secure and interoperable manner.
    /// </remarks>
    public const string Vc = "vc";

    /// <summary>
    /// Represents a verifiable presentation as specified in the W3C Recommendation.
    /// </summary>
    /// <remarks>
    /// This claim is used when a subject presents one or more verifiable credentials, allowing the verifier
    /// to check the authenticity and integrity of the credentials presented, facilitating trusted digital interactions.
    /// </remarks>
    public const string Vp = "vp";

    #endregion

    #region rfc9027 - SIP Priority Header

    /// <summary>
    /// Used to indicate the priority of a SIP message.
    /// </summary>
    /// <remarks>
    /// This claim is relevant in Session Initiation Protocol (SIP)-based communications, where it may influence routing,
    /// handling, and processing priorities of SIP messages, ensuring that critical communications are appropriately
    /// prioritized.
    /// </remarks>
    public const string Sph = "sph";

    #endregion

    #region RFC9200 - ACE Framework

    /// <summary>
    /// Specifies the ACE profile a token is used with, indicating its application in constrained environments.
    /// </summary>
    /// <remarks>
    /// This claim is significant in scenarios utilizing the Authentication and Authorization for Constrained
    /// Environments (ACE) framework, ensuring that tokens are applied in accordance with the specific requirements
    /// and constraints of the ACE profile in use.
    /// </remarks>
    public const string AceProfile = "ace_profile";

    /// <summary>
    /// Nonce provided by the Resource Server to the Authorization Server via the client, verifying token freshness.
    /// </summary>
    /// <remarks>
    /// This claim is used to ensure the freshness of a token in interactions between the Resource Server, the client,
    /// and the Authorization Server, mitigating against replay attacks by validating the uniqueness and timeliness
    /// of each token request.
    /// </remarks>
    public const string Cnonce = "cnonce";

    /// <summary>
    /// Lifetime of the token in seconds from the time the Resource Server first sees it, for devices with
    /// unsynchronized clocks.
    /// </summary>
    /// <remarks>
    /// This claim addresses challenges posed by devices with unsynchronized clocks by providing a relative measure
    /// of the token's validity, enhancing interoperability and security in distributed systems.
    /// </remarks>
    public const string Exi = "exi";

    #endregion

    #region RFC7643 - SCIM Roles and Groups

    /// <summary>
    /// Represents the roles associated with the subject, often used in System for Cross-domain Identity Management (SCIM).
    /// </summary>
    /// <remarks>
    /// This claim is used to convey the roles attributed to a subject, facilitating role-based access control (RBAC)
    /// and other authorization decisions in systems implementing SCIM or similar identity management protocols.
    /// </remarks>
    public const string Roles = "roles";

    /// <summary>
    /// Represents the groups that the subject belongs to, typically used in identity and access management.
    /// </summary>
    /// <remarks>
    /// This claim is used to convey group membership information, supporting group-based access control and
    /// enabling systems to make authorization decisions based on the groups a subject is associated with.
    /// </remarks>
    public const string Groups = "groups";

    /// <summary>
    /// Represents specific entitlements or permissions granted to the subject.
    /// </summary>
    /// <remarks>
    /// This claim is used to specify granular permissions or entitlements granted to a subject,
    /// allowing for precise control over access rights and enabling fine-grained authorization policies.
    /// </remarks>
    public const string Entitlements = "entitlements";

    #endregion

    #region OAuth JWT Introspection

    /// <summary>
    /// Contains the response from an OAuth 2.0 token introspection request.
    /// </summary>
    /// <remarks>
    /// This claim is typically used in scenarios where detailed token information is necessary for validating
    /// token status, scopes, and other attributes as part of OAuth 2.0 introspection processes.
    /// </remarks>
    public const string TokenIntrospection = "token_introspection";

    #endregion

    #region CDNI Claims - RFC9246

    /// <summary>
    /// Version of the claim set used in Content Delivery Network Interconnection (CDNI).
    /// </summary>
    /// <remarks>
    /// This claim facilitates interoperability in CDNI contexts by specifying the version of the claim set,
    /// ensuring that both the issuer and recipient of a JWT understand the structure and semantics of
    /// the claims contained within.
    /// </remarks>
    public const string Cdniv = "cdniv";

    /// <summary>
    /// Identifies critical claims within the CDNI claim set.
    /// </summary>
    /// <remarks>
    /// This claim is used to mark certain claims as critical within the context of CDNI,
    /// indicating that the JWT should be processed differently or not at all if these claims are not understood
    /// or cannot be fulfilled.
    /// </remarks>
    public const string Cdnicrit = "cdnicrit";

    /// <summary>
    /// Represents an IP address in CDNI scenarios.
    /// </summary>
    /// <remarks>
    /// This claim is used to convey IP address information within CDNI,
    /// supporting operations such as tokenized redirection or content delivery optimizations based
    /// on geographical or network-based criteria.
    /// </remarks>
    public const string Cdniip = "cdniip";

    /// <summary>
    /// Contains a URI in CDNI contexts.
    /// </summary>
    /// <remarks>
    /// This claim is utilized to reference specific resources or content within CDNI, allowing for dynamic
    /// content delivery configurations and optimizations based on the content identified by the URI.
    /// </remarks>
    public const string Cdniuc = "cdniuc";

    /// <summary>
    /// Expiration time setting for token renewal in CDNI.
    /// </summary>
    /// <remarks>
    /// This claim specifies the expiration time for a CDNI token, guiding the renewal process by indicating
    /// when a new token must be obtained to continue accessing CDNI content or services.
    /// </remarks>
    public const string Cdniets = "cdniets";

    /// <summary>
    /// Transport method for signed token renewal in CDNI.
    /// </summary>
    /// <remarks>
    /// This claim indicates the transport method to be used for renewing signed tokens in CDNI,
    /// ensuring secure and efficient token exchange mechanisms are employed for content delivery
    /// and interconnection services.
    /// </remarks>
    public const string Cdnistt = "cdnistt";

    /// <summary>
    /// Depth of the signed token in CDNI.
    /// </summary>
    /// <remarks>
    /// This claim provides information on the depth or hierarchy level of a signed token within CDNI,
    /// potentially influencing content delivery paths or access control decisions based on the token's
    /// scope and applicability.
    /// </remarks>
    public const string Cdnistd = "cdnistd";

    #endregion

    #region RFC9321 - Signature Validation

    /// <summary>
    /// Contains claims used for validating signatures, often in security contexts.
    /// </summary>
    /// <remarks>
    /// This claim set is essential for scenarios where signature validation is critical, providing necessary
    /// information to verify the authenticity and integrity of signed data or tokens in secure communications
    /// and transactions.
    /// </remarks>
    public const string SigValClaims = "sig_val_claims";

    #endregion

    #region OAuth Rich Authorization Requests (RAR)

    /// <summary>
    /// JSON array representing the authorization requirements for a specific resource or set of resources.
    /// </summary>
    /// <remarks>
    /// This claim is used in OAuth Rich Authorization Requests (RAR) to specify detailed authorization data
    /// for a transaction, enabling fine-grained access control and tailored authorization experiences.
    /// </remarks>
    public const string AuthorizationDetails = "authorization_details";

    #endregion
}
