# License Agreement

This License Agreement ("Agreement") is a legal agreement between you (as a person or entity, "You") and Abblix Limited Liability Partnership ("Copyright Holder") for the OIDC Server ("Software").

**ATTENTION!** Please thoroughly examine the terms and conditions in this License Agreement before operating the Software. By using the Software, you agree to be bound by the terms set forth in this License Agreement. If you do not agree to these terms, you have no right to use the Software and must promptly uninstall it from your System.

## 1. Definitions
1.1. "Software" refers to the "OIDC Server" software, including any accompanying materials, updates, and extensions, the copyright of which belongs to Abblix Limited Liability Partnership. The Software is certified by the OpenID Foundation ([openid.net/certification](https://openid.net/certification/)). The source code is publicly viewable at [github.com/Abblix/Oidc.Server](https://github.com/Abblix/Oidc.Server) for evaluation purposes, subject to all restrictions in this Agreement. The full text of this Agreement is available at [oidc.abblix.com/license](https://oidc.abblix.com/license).

1.2. "System" refers to an operating system, virtual machine, or equipment, including a server, on which the Software is installed and/or used.

1.3. "User" or "You" refers to a natural or legal person who installs and/or uses the Software on their behalf or legally owns a copy of the Software. If the Software was downloaded or acquired on behalf of a legal entity, the term "User" or "You" refers to the legal entity for which the Software was downloaded or acquired, and is accepting this Agreement through an authorized representative.

1.4. "Partners" refers to organizations that distribute the Software based on agreement with the Copyright Holder.

1.5. "Software Extensions" are additional software components and software solutions provided by the Copyright Holder that extend the functionality of the Software and may require the purchase of a separate license or an extension of an existing license. Software Extensions can be provided both free of charge and paid. You can obtain more detailed information before receiving such extensions.

1.6. "Client" or "Client Application" refers to software programs that interact with the Software (OpenID Connect server) to authenticate users and obtain tokens for accessing protected resources. Each unique client application is identified by a distinct client identifier (client_id) registered with the Software.

1.7. "Issuer" refers to an authorization server instance as defined in the OAuth 2.0 specification (RFC 6749) and OpenID Connect Core specification.

1.8. **System Definition for Licensing Purposes.** For purposes of determining license compliance:
   (a) A single physical server or virtual machine (VM) running one instance of the Software with one public hostname constitutes one System;
   (b) Containerized deployments (Docker containers, Kubernetes pods, or similar technologies) running on a single physical or virtual host and serving one public hostname are considered part of that single System and do not constitute separate Systems;
   (c) Multiple physical servers or VMs serving one public hostname for load-balancing, high availability, or failure-resistance purposes are considered one System;
   (d) Multiple instances of the Software serving different hostnames or independent services constitute multiple Systems, regardless of whether they run on the same physical or virtual host or on separate hosts;
   (e) Geo-distributed deployments spanning multiple regions or data centers are considered one System if: (i) all servers serve the same primary public hostname(s) accessible to end users, and (ii) regional hostnames (if any) exist solely for infrastructure routing, monitoring, or failover purposes. If regional instances are designed to be independently accessible via distinct public hostnames for normal user operations (even if the primary scenario does not require users to use these additional hostnames), each regional deployment constitutes a separate System;
   (f) Non-production environments (development, testing, staging, beta, QA, or similar) used solely for internal development, quality assurance, or pre-production testing are not counted as separate Systems, provided they are not accessible to external end users or used to provide production services. Each production environment constitutes a separate System;
   (g) Installation limits for commercial licenses vary by license type and are specified in your purchase agreement and at [abblix.com/abblix-oidc-server-pricing](https://www.abblix.com/abblix-oidc-server-pricing).

## 2. License Grant
2.1. You are granted a non-exclusive license to use the Software within the scope of the functionality described on the Copyright Holder's official website, available at [oidc.abblix.com/functionality](https://oidc.abblix.com/functionality), provided that you comply with all restrictions and conditions specified in this License Agreement. This license does not grant sublicensing or redistribution rights to third parties. To obtain sublicensing or redistribution rights, you must purchase a separate type of license.

2.2. **Prohibited Actions.** You may not:
   (a) Modify, alter, translate, adapt, or create derivative works from the Software;
   (b) Reverse engineer, decompile, or disassemble the Software;
   (c) Distribute, sublicense, sell, rent, or lease the Software;
   (d) Remove, obscure, or circumvent copyright, proprietary notices, or access controls.

2.3. You may not use the Software in commercial projects, except as provided in clause 2.5. If you wish to use the Software for non-commercial purposes, you may download and access the Software free of charge, subject to all license terms and technical limits specified in Section 2.3.1. Examples of non-commercial projects include:
   - Free educational projects;
   - Games without monetization;
   - Test versions of commercial systems for piloting/demonstrating performance in internal non-commercial environments without generating profit.
If your product generates revenue through advertising, paid subscriptions, or any commercial means, you may not use the Software under the free non-commercial license.

2.3.1. **Non-Commercial License Technical Limits.** Non-commercial licenses granted at no charge are subject to the following technical restrictions:
   (a) **Client Limit**: Maximum 2 (two) unique client applications may be used;
   (b) **Issuer Limit**: Maximum 1 (one) issuer may be used;
   (c) **Enforcement**: These limits are enforced according to the License Limit Enforcement Framework specified in Section 2.7. Violations must be remedied by either: (i) reducing the number of clients or issuers to compliant levels, or (ii) upgrading to a commercial license under Section 2.5 or Section 2.6.

2.4. If the laws of your country prohibit you from using the Software, you are not authorized to use it, and you agree to comply with all applicable laws and regulations concerning your use of the Software.

2.5. If you wish to use the Software in commercial projects, or if your projects have a commercial component in any way, you may download and use the Software during the term upon payment of the applicable license fee, in accordance with the terms of this Agreement.

2.6. **Commercial License Types.** The Copyright Holder offers the following commercial license types:

   (a) **Standard License** - For use of the Software in your commercial applications and services. Installation limits and specific terms are defined at the time of purchase.

   (b) **Redistribution License** - Permits redistribution of the Software as part of your commercial products, subject to additional terms and conditions:
      (i) **Software Redistribution**: You may redistribute the Software as an integrated component of your commercial product to your end customers;
      (ii) **License Key Management**: All end-customer license keys must be requested through Copyright Holder's designated channels. You must provide accurate deployment specifications but may not generate, modify, or transfer license keys. Copyright Holder will provision keys for your distribution or direct delivery to end customers;
      (iii) **Your Responsibilities**: You are responsible for managing customer relationships, collecting deployment requirements, and ensuring accurate specifications are provided;
      (iv) **End Customer Restrictions**: Your end customers are bound by the same restrictions as other licensees under this Agreement.

   (c) **Pricing and Detailed Terms.** Current pricing, installation limits, and detailed license comparisons are available at:
       - Pricing: [abblix.com/abblix-oidc-server-pricing](https://www.abblix.com/abblix-oidc-server-pricing)
       - License Comparison: [abblix.com/abblix-licenses-support-agreements](https://www.abblix.com/abblix-licenses-support-agreements)

   (d) **Purchase Agreement Controls.** The specific terms of your license (type, installation limits, duration, pricing) are governed by your purchase agreement or order confirmation. In the event of conflict between this License Agreement and your purchase agreement, the purchase agreement shall control with respect to commercial terms.

   (e) **Commercial License Technical Parameters.** Commercial licenses include the following technical parameters:
      (i) **Client Limit**: The maximum number of client applications permitted, as specified in your purchase agreement;
      (ii) **Issuer Limit**: The maximum number of issuers permitted, as specified in your purchase agreement;
      (iii) **Valid Issuers**: An optional whitelist of specific issuer URLs permitted under the license;
      (iv) **License Period**: Start date (NotBefore), expiration date (ExpiresAt), and optional grace period after expiration;
      (v) **Enforcement**: These limits are enforced according to the License Limit Enforcement Framework specified in Section 2.7. Violations must be remedied by either: (a) reducing the number of clients or issuers to compliant levels, or (b) upgrading to a higher-tier commercial license or purchasing additional capacity.

   (f) **Development Licenses for Commercial License Holders.** Holders of valid commercial production licenses are entitled to receive development licenses at no additional charge for use in non-production environments:
      (i) **Eligibility**: Available to any holder of a valid, active commercial license for production use;
      (ii) **Purpose**: Development licenses are provided exclusively for internal development, testing, staging, quality assurance, and other non-production purposes as defined in Section 1.8(f);
      (iii) **Technical Restrictions**: Development licenses are technically bound to non-production environments through one or more of the following mechanisms:
         - Restriction to internal issuer hostnames (e.g., auth.internal.example.com, localhost, *.local);
         - Restriction to non-routable IP addresses (e.g., 127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16);
         - Restriction to development-specific issuer URLs containing identifiers such as "dev", "test", "staging", "qa", "beta", or similar;
         - Other technical indicators that prevent use in production environments accessible to external end users;
      (iv) **Enforcement**: Development licenses are technically restricted to non-production environments. Production use is blocked by the Software;
      (v) **No Production Use**: Development licenses must not be used to provide authentication services to external end users or in any production environment. Any such use constitutes a violation of this License Agreement;
      (vi) **Eligibility Verification**: Development licenses are available upon verification of active commercial license status through Copyright Holder's designated process;
      (vii) **Term**: Development licenses remain valid for the duration of the associated commercial production license. Upon expiration or termination of the production license, all associated development licenses are automatically terminated;
      (viii) **No Separate Limits**: Development license usage does not count against the client or issuer limits of the associated production license, provided the development license is used solely for non-production purposes as defined herein.

2.7. **License Limit Enforcement Framework.** All licenses with client and issuer limits are subject to the following enforcement framework:

   (a) **Your Responsibility**: You acknowledge and agree that You are solely responsible for monitoring Your usage and ensuring compliance with the limits specified in your license. Any usage exceeding these limits constitutes a violation of this License Agreement. You must remedy such violations as soon as possible by the means specified for your license type. The Software may generate warnings when limits are approached or exceeded, but You must not rely on these warnings or their absence for compliance monitoring. Your obligation to comply with license limits exists at all times regardless of whether warnings are generated.

   (b) **Technical Enforcement**: The Software may generate warnings when usage approaches or exceeds license limits. Technical enforcement mechanisms do not modify your contractual obligation to comply with licensed limits at all times. Any temporary operation beyond limits does not constitute authorization for such use.

   (c) **Consequences of Non-Compliance**: Failure to remedy violations of these limits may result in termination of Your license under Section 3.5, in addition to any other remedies available to the Copyright Holder under this Agreement or applicable law.

## 3. Activation and Duration
3.1. When installing the Software, the period of use of the Software is indicated at the time of purchase or upon receipt of the Software free of charge under certain conditions in accordance with Section 2 of this agreement.

3.2. If you obtain the Software from a Partner, the useful life of the Software may be determined between you and the Partner.

3.3. The Software can only be installed on platforms suitable for its use. The Copyright Holder does not provide support for the following situations: copies of the Software installed on platforms not specified on the official website page, available at [oidc.abblix.com/requirements](https://oidc.abblix.com/requirements); support requests not related to the normal use of the Software; or support requests arising from the use of third-party products that either prohibit or do not function with the Software.

3.4. The license period for the Software can be verified on the official website page at [oidc.abblix.com/license-check](https://oidc.abblix.com/license-check).

3.5. **Termination for Breach.**

   (a) **Immediate Termination.** The Copyright Holder may terminate this Agreement immediately upon written notice for material breaches that cannot be reasonably cured, including but not limited to:
      (i) Unauthorized modification, reverse engineering, or redistribution of the Software;
      (ii) Removal or circumvention of license key protection or technical controls;
      (iii) Forgery, unauthorized generation, or modification of license keys;
      (iv) Violation of intellectual property rights specified in Section 10;
      (v) Use of the Software in violation of export control laws (Section 12).

   (b) **Termination with Notice.** For all other breaches, the Copyright Holder shall provide thirty (30) days' written notice (as defined in Section 11.7) specifying the breach. You shall have thirty (30) days from receipt of notice to cure the breach. If the breach is not cured within this period, the Copyright Holder may terminate this Agreement upon expiration of the cure period.

   (c) **Effect of Termination.** Upon termination, You must immediately cease all use of the Software, uninstall all copies, and certify destruction in writing to the Copyright Holder within ten (10) days.

3.6. **License Key Generation and Provisioning.**

   (a) **Authorized Provisioning.** All license keys for the Software are generated and provided exclusively by the Copyright Holder's authorized personnel. License keys cannot be generated outside the Copyright Holder by any person or entity. License keys cannot be self-generated, transferred, redistributed, or modified by licensees.

   (b) **Key Delivery.** License keys are delivered to licensees through secure channels designated by the Copyright Holder.

   (c) **Key Contents.** Each license key is digitally signed and contains the license parameters necessary to enforce this Agreement.

   (d) **Key Security.** You are responsible for:
      (i) Maintaining the confidentiality of your license keys;
      (ii) Preventing unauthorized access to or use of your license keys;
      (iii) Notifying the Copyright Holder immediately if you suspect a license key has been compromised;
      (iv) Using license keys only for the authorized purposes specified in your license agreement.

   (e) **Key Replacement.** The Copyright Holder may replace or revoke license keys:
      (i) Upon request due to suspected compromise or loss;
      (ii) When upgrading or modifying license terms;
      (iii) Upon detection of unauthorized use or redistribution;
      (iv) When migrating to new deployment environments.

   (f) **Technical Verification.** The Software validates license keys through cryptographic and technical controls to enforce the terms of this Agreement.

   (g) **No Self-Service Generation.** You acknowledge and agree that:
      (i) License keys cannot be generated without access to the Copyright Holder's private signing keys;
      (ii) Attempting to forge, modify, or reverse-engineer license keys is strictly prohibited and constitutes a material breach of this Agreement;
      (iii) All license modifications require obtaining a new license key from the Copyright Holder's authorized personnel.

   (h) **License Expiration and Renewal.**
      (i) **Expiration**: License keys have a defined expiration date. Use of the Software beyond the expiration date without a valid license constitutes a violation of this Agreement;
      (ii) **Grace Period After Expiration**: License keys may include a technical grace period after expiration to prevent service disruption during renewal processing. The existence and duration of any grace period is specified in your license key. If You renew during the grace period, the number of days used during the grace period will be deducted from your new license term. For example, if You use seven (7) days of a grace period before renewing for a one (1) year term, your new license will expire 358 days from renewal (not 365 days). You remain obligated to renew before expiration; any grace period does not extend your total paid license term or constitute permission to operate without a valid license;
      (iii) **No Automatic Renewal**: License keys do not automatically renew. You must explicitly request and purchase license renewal from the Copyright Holder to continue using the Software beyond the expiration date;
      (iv) **Renewal Process**: To renew your license, contact the Copyright Holder's authorized personnel before the expiration date, complete the renewal purchase, and receive a new license key with an updated validity period.

3.7. **Software Updates and Maintenance.**

   (a) **Included Updates.** During the active license term, You are entitled to:
      (i) Bug fixes and security patches for the licensed version;
      (ii) Minor version updates (e.g., 1.x to 1.y) within the same major version;
      (iii) Access to updated documentation.

   (b) **Major Version Upgrades.** Upgrades to new major versions (e.g., 1.x to 2.x) may require additional license fees at the Copyright Holder's then-current pricing.

   (c) **End of Life.** The Copyright Holder will provide at least six (6) months' notice before discontinuing support for a major version. Supported versions are listed at [oidc.abblix.com/versions](https://oidc.abblix.com/versions).

3.8. **License Compliance Verification.**

   (a) **Audit Rights.** The Copyright Holder may, upon thirty (30) days' written notice, audit Your use of the Software to verify compliance with this Agreement. Audits shall:
      (i) Occur no more than once per calendar year unless a prior audit revealed non-compliance exceeding five percent (5%);
      (ii) Be conducted during normal business hours at Your facilities or via remote access;
      (iii) Be performed by the Copyright Holder or an independent third-party auditor bound by confidentiality obligations;
      (iv) Not unreasonably interfere with Your business operations.

   (b) **Audit Scope.** Audits may include review of:
      (i) Installation records and deployment configurations;
      (ii) License keys and activation records;
      (iii) System logs relevant to Software usage.
      The Copyright Holder shall not access customer data, source code, or other confidential business information unrelated to license compliance.

   (c) **Confidentiality.** The Copyright Holder agrees to maintain confidentiality of all information obtained during audits, except as required by law.

   (d) **Non-Compliance Remedies.** If an audit reveals underpayment or over-deployment exceeding five percent (5%) of amounts due, You shall:
      (i) Pay the shortfall within thirty (30) days;
      (ii) Reimburse the Copyright Holder's reasonable audit costs.
      If underpayment is less than five percent (5%), the Copyright Holder bears audit costs.

## 4. Data Processing and Privacy

4.1. **Library Architecture.** The Software is a library integrated into your applications. It does not transmit data to the Copyright Holder or any third parties. All data processing occurs within your infrastructure under your control.

4.2. **License Activation Data.** The Copyright Holder collects and processes license activation information (license key, activation date, email address provided during purchase) for the sole purpose of license validation and customer support. This data is retained for the license term plus seven (7) years for legal and accounting purposes, then securely deleted. For data subject rights requests (access, deletion, portability), contact info@abblix.com.

4.3. **Your Compliance Responsibility.** You are solely responsible for ensuring that your use of the Software complies with applicable data protection laws, including GDPR, CCPA, and other privacy regulations in your jurisdiction.

4.4. **Agreement Duration and Termination.** This Agreement shall be in effect for the period specified in the license issued to you upon payment of the applicable license fee for the Software. The Copyright Holder may terminate this Agreement in accordance with the conditions set forth in clause 3.5. You may also terminate this Agreement for any reason by ceasing all use of the Software. Upon termination of this Agreement, no refund will be provided to you, in whole or in part, and you must immediately stop using the Software and provide evidence of such termination to the Copyright Holder upon request.

4.5. **Security Breach Notification.** In the event of a security breach affecting license activation data collected under Section 4.2, the Copyright Holder will:
   (a) Notify You within seventy-two (72) hours of becoming aware of the breach;
   (b) Provide details of the breach, data affected, and remedial measures taken;
   (c) Cooperate with You to meet Your regulatory notification obligations under applicable data protection laws.

## 5. Software Rights
5.1. The Software is wholly owned by the Copyright Holder and is licensed to You, not sold. The Software is protected by copyright laws and international copyright treaties, as well as other intellectual property laws and treaties. Except for the limited rights of use granted herein, all rights, title, and interest in the Software, including patents, copyrights, and trademarks in and to the Software, accompanying printed materials, and any copies of the Software, belong to the Copyright Holder.

## 6. Communications and Notifications

6.1. **Essential Communications.** By using the Software, you agree to receive essential service-related communications from the Copyright Holder, including:
   (a) License expiration and renewal notifications;
   (b) Critical security updates and vulnerabilities;
   (c) Important changes to this License Agreement;
   (d) License compliance and activation issues.

6.2. **Promotional Communications (Optional).** You may opt-in to receive promotional materials, product updates, and marketing communications from the Copyright Holder and its Partners. You can:
   (a) Opt-out at any time by emailing info@abblix.com with subject "Unsubscribe";
   (b) Use the unsubscribe link provided in each promotional email;
   (c) Withdraw consent without affecting your license rights.

6.3. **Privacy.** The Copyright Holder will not sell, rent, or share your email address with third parties for their marketing purposes without your explicit consent.

## 7. Restrictions and Compliance

7.1. You may not rent, lease, or lend the Software.

7.2. Violation of intellectual property rights in the Software may result in civil, administrative, or criminal liability as provided by applicable law.

7.3. You agree that the Software may be used by you only in accordance with its intended use and must not violate local laws.

7.4. **OpenID Foundation Certification.**

   (a) **Certification Status.** The Software has been tested and certified by the OpenID Foundation as conformant to the following profiles:

      **OpenID Provider Profiles** ([openid.net/certification/#OPENID-OP-P](https://openid.net/certification/#OPENID-OP-P)):
      (i) Basic OP
      (ii) Implicit OP
      (iii) Hybrid OP
      (iv) Config OP
      (v) Dynamic OP
      (vi) Form Post OP
      (vii) 3rd Party-Init OP

      **Logout Profiles** ([openid.net/certification/#OPENID-OP-LP](https://openid.net/certification/#OPENID-OP-LP)):
      (viii) RP-Initiated OP
      (ix) Session OP
      (x) Front-Channel OP
      (xi) Back-Channel OP

   (b) **What Certification Means.** OpenID Foundation certification verifies that the Software:
      (i) Implements OpenID Connect and OAuth 2.0 specifications correctly;
      (ii) Passes comprehensive conformance tests (630+ test cases);
      (iii) Interoperates with other certified implementations;
      (iv) Adheres to security best practices defined by the OpenID Foundation.

   (c) **Independent Verification.** You can independently verify the Software's certification status at [openid.net/certification](https://openid.net/certification/) by searching for Organization: "Abblix LLP" and Implementation: "OIDC Server v1" in the certified implementations list.

   (d) **No Warranty Extension.** OpenID Foundation certification validates technical conformance to specifications but does NOT extend the warranties or liability terms in Sections 8 and 9 of this Agreement.

7.5. **Standards Compliance.** The Software implements the following specifications:
   (a) OpenID Connect Core 1.0
   (b) OAuth 2.0 (RFC 6749)
   (c) OAuth 2.0 Security Best Current Practice
   (d) Additional specifications as documented at [oidc.abblix.com/functionality](https://oidc.abblix.com/functionality)

7.6. **No Other Certifications.** Except as expressly stated in Section 7.4, the Copyright Holder does not claim or warrant any other security certifications (such as SOC 2, ISO 27001) unless separately provided in writing.

7.7. **Source Code Transparency.**

   (a) **Public Repository.** The Software source code is maintained in a public repository at [github.com/Abblix/Oidc.Server](https://github.com/Abblix/Oidc.Server) to enable:
      (i) Security audits and code reviews by potential customers;
      (ii) Verification of OpenID Foundation certification claims;
      (iii) Technical evaluation before purchase;
      (iv) Transparency in security practices and implementation.

   (b) **Not Open Source.** Public availability of source code does NOT constitute open-source licensing. The Software remains subject to all restrictions in this Agreement, including prohibition on modification, redistribution, and derivative works (Section 2.2).

   (c) **GitHub Terms.** Your access to the GitHub repository is subject to GitHub's Terms of Service. The Copyright Holder may restrict or revoke repository access at any time.

## 8. Limited Warranty and Disclaimer

8.1. **Limited Warranty (Commercial Licenses Only).** For commercial licenses purchased under Section 2.5 and Section 2.6, the Copyright Holder warrants that, for a period of ninety (90) days from the earlier of (i) license activation date or (ii) license purchase date ("Warranty Period"), the Software will materially conform to the functionality described in the Documentation version corresponding to your licensed Software release, provided that:
   (a) You use the latest releases of supported versions listed at [oidc.abblix.com/versions](https://oidc.abblix.com/versions);
   (b) The Software is properly installed in accordance with documentation;
   (c) You comply with all terms of this License Agreement.

For purposes of this warranty, "materially conform" means the Software performs the core functions described in the Documentation in all significant respects. Minor variations that do not constitute material non-conformity include: (i) cosmetic interface differences that do not impair functionality; (ii) performance variations under twenty percent (20%) of documented specifications under normal operating conditions; (iii) features explicitly marked as "beta", "experimental", or "preview" in the Documentation; and (iv) issues resolved in updates provided during the Warranty Period.

This limited warranty does NOT apply to non-commercial licenses granted at no charge under Section 2.3 (see Section 8.8 for non-commercial license terms).

8.2. **Exclusive Remedy.** Your exclusive remedy for breach of the limited warranty in Section 8.1 shall be, at the Copyright Holder's sole discretion: (i) repair or replacement of the non-conforming Software; (ii) refund of the license fee paid; or (iii) provision of workarounds or patches to achieve material conformity. This remedy is contingent upon You providing written notice of the non-conformity to info@abblix.com within the Warranty Period.

8.3. **Warranty Exclusions.** The limited warranty in Section 8.1 does not apply to defects, errors, or failures resulting from:
   (a) Modification, alteration, or unauthorized use of the Software;
   (b) Use of unsupported versions or platforms;
   (c) Failure to properly install or configure the Software;
   (d) Use in combination with incompatible third-party software;
   (e) Your violation of this License Agreement.

8.4. **Support Services.**
   (a) **Standard Support Agreement** - Included with all commercial licenses. Provides basic support services with defined response times.
   (b) **Extended Support Agreement** - Available for Enterprise licenses or for additional payment. Provides enhanced support services with higher service levels.
   (c) Details available at [abblix.com/abblix-licenses-support-agreements](https://www.abblix.com/abblix-licenses-support-agreements).

8.5. **Acknowledgment.** You acknowledge that:
   (a) No software is entirely error-free;
   (b) The Software's functionality depends on proper installation and configuration;
   (c) Your use of the Software is at your own risk beyond the limited warranty provided.

8.6. **DISCLAIMER OF IMPLIED WARRANTIES.** TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE COPYRIGHT HOLDER AND ITS PARTNERS EXPRESSLY DISCLAIM ALL WARRANTIES NOT EXPLICITLY STATED IN SECTION 8.1, WHETHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. SOME JURISDICTIONS DO NOT ALLOW THE EXCLUSION OF IMPLIED WARRANTIES, SO THE ABOVE EXCLUSION MAY NOT APPLY TO YOU.

8.7. **Consumer Rights.** Nothing in this Agreement excludes or limits any statutory rights that cannot be lawfully excluded or limited, including consumer protection rights under applicable law.

8.8. **Non-Commercial License Disclaimer.** For non-commercial licenses granted at no charge under Section 2.3, the Software is provided strictly "AS IS" WITHOUT WARRANTY OF ANY KIND, express or implied. You acknowledge and agree that You use the Software entirely at Your own risk. The limited warranty in Section 8.1 does NOT apply to non-commercial licenses. Notwithstanding the foregoing, the Copyright Holder does not disclaim liability that cannot be excluded under applicable law, including liability for fraud, gross negligence, willful misconduct, or death/personal injury caused by the Copyright Holder's negligence. The liability cap in Section 9.1 ($1,000 USD) applies only to such non-excludable claims.

## 9. Limitation of Liability

9.1. **Liability Cap.** To the maximum extent permitted by applicable law, the Copyright Holder and/or its partners shall not be liable for any loss and/or damage (including losses due to lost commercial profits, business interruption, loss of information, or other property damage) arising from or in connection with the use or inability to use the software, even if the Copyright Holder and its partners have been notified of the possible occurrence of such losses and/or damage. In any event, the aggregate liability of the Copyright Holder and its partners under any provision of this License Agreement shall not exceed the greater of:
   (a) The total license fees paid by You to the Copyright Holder in the twelve (12) months immediately preceding the event giving rise to liability; or
   (b) Ten Thousand United States Dollars ($10,000 USD).

For non-commercial licenses granted at no charge, the liability cap shall be One Thousand United States Dollars ($1,000 USD).

9.2. **Enforceability.** The limitations set forth in this Section 9 shall apply to the fullest extent permitted by applicable law. Some jurisdictions do not allow the limitation or exclusion of liability for incidental or consequential damages; in such jurisdictions, the above limitation may not apply to You, and the Copyright Holder's liability shall be limited to the maximum extent permitted by applicable law.

## 10. Intellectual Property Rights and Confidentiality

10.1. You agree that the Software, documentation, and all other objects of copyright, systems, ideas, methods of work, and other information contained in the Software, as well as trademarks, are the intellectual property of the Copyright Holder or its Partners. This License Agreement does not grant you any rights to use intellectual property, including trademarks and service marks of the Copyright Holder or its Partners, except for the rights granted by this License Agreement.

10.2. **Confidentiality.** The Software is confidential and proprietary information. You agree to maintain the confidentiality of the Software and not to disclose any confidential information related to the Software to any third party without the prior written consent of the Copyright Holder.

10.3. **Confidentiality Exceptions.** The confidentiality obligations in Section 10.2 do not apply to information that:
   (a) Was publicly available before disclosure to You;
   (b) Becomes publicly available through no fault of Yours;
   (c) Was independently developed by You without reference to the Software;
   (d) Is required to be disclosed by law, regulation, or court order (provided You give prompt written notice to the Copyright Holder to allow the Copyright Holder to seek protective measures).

## 11. Governing Law and Dispute Resolution

11.1. **Governing Law and Jurisdiction.** This License Agreement is governed by the laws of the Republic of Kazakhstan. Any disputes, controversies, or claims arising out of or relating to this License Agreement, or the breach, termination, or invalidity thereof, shall be subject to the exclusive jurisdiction of the specialized inter-district economic court of Astana city, Republic of Kazakhstan.

11.2. **Language of Proceedings.** Legal proceedings shall be conducted in accordance with the procedural rules of the specialized inter-district economic court of Astana city, which may permit submissions in Kazakh, Russian, or English. Each party bears responsibility for translation costs for documents it submits. Parties may request clarification from the court regarding acceptable languages prior to filing.

11.3. **Negotiation Before Litigation.** In the event of any dispute, controversy, or claim arising out of or relating to this License Agreement, or the breach, termination, or invalidity thereof, the parties shall first seek to resolve the dispute through good faith negotiations. This process should involve direct communication between the parties or their designated representatives with the aim to reach an amicable settlement. If the dispute cannot be resolved through negotiation within thirty (30) days, then either party may proceed to litigation as described in Section 11.1.

11.4. **Severability.** If any provision of this License Agreement is held to be void, voidable, unenforceable, or illegal, the remaining provisions of this License Agreement will remain in full force and effect. In the event of a conflict between the terms of this Agreement and the terms of any software product license agreement concluded between you and the Partners or the Copyright Holder, the terms of such a license agreement shall prevail; in all other respects, the terms of this Agreement and such agreement shall apply.

11.5. **External Document Conflicts.** In the event of a conflict between the terms of this License Agreement and information provided on external websites (including but not limited to oidc.abblix.com, GitHub repositories, or third-party documentation):
   (a) This License Agreement shall prevail for all legal rights, obligations, warranties, and limitations of liability;
   (b) External website content is provided for informational and technical reference purposes only;
   (c) You acknowledge that external content may be updated without notice and does not modify the terms of this Agreement unless explicitly incorporated by reference;
   (d) Any discrepancies should be reported to info@abblix.com for clarification.

11.6. **Entire Agreement.** This Agreement, together with any purchase agreement or order confirmation referencing this Agreement, constitutes the entire agreement between You and the Copyright Holder regarding the Software and supersedes all prior or contemporaneous understandings, agreements, representations, and warranties, whether written or oral, regarding such subject matter. This Agreement may be modified only by a written amendment signed by authorized representatives of both parties. No provision of this Agreement may be waived except by a writing signed by the party against whom the waiver is sought to be enforced.

11.7. **Notices.** All notices required under this Agreement must be in writing and shall be deemed given when: (a) delivered personally; (b) sent by confirmed email to the addresses specified in Section 17 (Contact Information); or (c) three (3) business days after deposit with an internationally recognized courier service with tracking capability. Either party may update its notice address by providing written notice to the other party in accordance with this section.

## 12. Export Controls

12.1. **Encryption Notice.** This Software uses encryption technology provided by .NET for standard OpenID Connect and OAuth 2.0 security protocols. The Software does not implement custom cryptographic functions. The encryption functionality is publicly available and widely distributed.

12.2. **User Representations.** You represent and warrant that:
   (a) You are not located in, under the control of, or a national or resident of any country subject to comprehensive U.S. or EU economic sanctions;
   (b) You are not identified on any government restricted party list, including the U.S. Treasury Department's Specially Designated Nationals List, the U.S. Commerce Department's Denied Persons List, or equivalent lists;
   (c) You will not use the Software in violation of any applicable export control laws or regulations.

12.3. **Prohibited Countries and Uses.** The Software may not be downloaded, exported, re-exported, or transferred:
   (a) To or within Cuba, Iran, North Korea, Syria, or the Crimea region;
   (b) To any person or entity on government restricted party lists;
   (c) For use in the development, production, or stockpiling of nuclear, chemical, or biological weapons;
   (d) For use in missile technology or unmanned air vehicle systems.

12.4. **Compliance Responsibility.** You are solely responsible for compliance with all applicable export control laws and regulations in your jurisdiction and any jurisdiction where the Software is used.

## 13. Intellectual Property Claims

13.1. **Cooperative Defense Support.** If You receive a third-party claim alleging that the Software, when used in accordance with this Agreement, infringes a patent, copyright, or trademark, the Copyright Holder will cooperate with Your defense by:
   (a) Providing documentation demonstrating the Copyright Holder's ownership of intellectual property rights in the Software, including copyright registrations and patent documentation;
   (b) Providing technical documentation and evidence regarding the Software's implementation and operation;
   (c) Making reasonable efforts to provide expert testimony or technical consultation, if requested and commercially reasonable;
   (d) Providing information about the Software's certification by the OpenID Foundation and compliance with industry standards.

13.2. **Notification and Cooperation.** To receive the support described in Section 13.1, You must:
   (a) Promptly notify the Copyright Holder in writing of the claim within thirty (30) days of becoming aware;
   (b) Provide reasonable details of the claim, including at a minimum: (i) identification of the allegedly infringing Software components; (ii) description of the alleged intellectual property rights at issue; (iii) copies of any complaint, demand letter, or cease-and-desist notice received; and (iv) any other information reasonably available to assist the Copyright Holder in understanding the claim;
   (c) Allow the Copyright Holder to participate in discussions related to the defense, at the Copyright Holder's discretion.

13.3. **No Financial Indemnification.** The Copyright Holder does not assume financial responsibility for Your legal defense costs, damages, settlements, or attorney fees related to intellectual property claims. You remain solely responsible for Your own legal defense and any resulting financial obligations. The support provided under Section 13.1 is documentary and technical in nature only.

13.4. **Exclusions.** The Copyright Holder has no obligation to provide support for claims arising from:
   (a) Modification of the Software by You or third parties not authorized by the Copyright Holder;
   (b) Use of the Software in combination with third-party products, data, or services not specified in the documentation;
   (c) Use of superseded or unsupported versions of the Software after being provided with updates;
   (d) Use of the Software in violation of this Agreement or applicable law;
   (e) Compliance with Your specific designs, specifications, or instructions.

13.5. **Remedial Actions.** If the Software is, or in the Copyright Holder's opinion is likely to be, subject to a valid infringement claim, the Copyright Holder may at its sole option and expense:
   (a) Procure the right for You to continue using the Software;
   (b) Replace or modify the Software to be non-infringing while maintaining substantially equivalent functionality;
   (c) Terminate the license and refund pro-rata license fees for the unused portion of the prepaid term (commercial licenses only).

13.6. **Limitation of Remedies.** This Section 13 states the Copyright Holder's entire obligation and Your exclusive remedy regarding intellectual property infringement claims related to the Software. The Copyright Holder disclaims all other warranties and remedies, whether express or implied, related to intellectual property infringement.

## 14. Force Majeure

14.1. **Force Majeure Events.** Neither party shall be liable for any failure or delay in performance under this Agreement due to causes beyond its reasonable control, including but not limited to war, terrorism, civil unrest, riots, strikes, labor disputes, government actions, epidemics, pandemics, natural disasters, internet service provider failures, power outages, or telecommunications failures.

14.2. **Notification and Resumption.** The affected party shall:
   (a) Promptly notify the other party in writing of the force majeure event and its expected duration;
   (b) Use commercially reasonable efforts to mitigate the effects of the force majeure event, which may include implementing backup systems, rerouting services, or providing alternative access methods where feasible and cost-effective under the circumstances;
   (c) Resume performance as soon as reasonably practicable after the force majeure event ceases.

14.3. **License Term Extension.** If a force majeure event prevents Your use of the Software for more than thirty (30) consecutive days, Your license term shall be extended by the period of non-use, provided You notify the Copyright Holder within ten (10) days after the force majeure event ends.

14.4. **Termination Right.** If a force majeure event continues for more than ninety (90) days, either party may terminate this Agreement upon written notice to the other party. In such case, the Copyright Holder shall refund pro-rata license fees for the unused portion of any prepaid term.

## 15. Assignment

15.1. **Restrictions on Assignment.** You may not assign, transfer, delegate, or sublicense this Agreement or any rights or obligations hereunder without the prior written consent of the Copyright Holder, which consent shall not be unreasonably withheld. Any attempted assignment in violation of this section is void.

15.2. **Permitted Transfers.** Notwithstanding Section 15.1, You may assign this Agreement without consent in connection with a merger, acquisition, corporate reorganization, or sale of all or substantially all of Your assets related to the business using the Software, provided that: (a) the assignee agrees in writing to be bound by all terms of this Agreement; and (b) You provide written notice to the Copyright Holder within thirty (30) days of the assignment.

15.3. **Copyright Holder Assignment.** The Copyright Holder may assign this Agreement without restriction, including in connection with a merger, acquisition, corporate reorganization, or sale of assets.

15.4. **Effect of Assignment.** Any permitted assignment shall not relieve the assigning party of its obligations under this Agreement unless the other party agrees in writing to release such obligations.

## 16. Survival

16.1. **Surviving Provisions.** The following sections shall survive termination or expiration of this Agreement: Section 4 (Data Processing and Privacy), Section 5 (Software Rights), Section 9 (Limitation of Liability), Section 10 (Intellectual Property Rights and Confidentiality), Section 11 (Governing Law and Dispute Resolution), Section 13 (Intellectual Property Claims - for claims arising during the term), Section 14 (Force Majeure), Section 15 (Assignment), and this Section 16 (Survival).

## 17. Contact Information

**Copyright Holder**: Abblix Limited Liability Partnership

**Website**: [abblix.com](https://www.abblix.com)

**Email**: [info@abblix.com](mailto:info@abblix.com)

**Support**: [support@abblix.com](mailto:support@abblix.com)

**Data Protection Officer**: [info@abblix.com](mailto:info@abblix.com)

---

*Last Updated: October 22, 2025*
