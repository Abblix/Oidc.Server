# License Agreement

This License Agreement ("Agreement") is a legal agreement between you (as a person or entity, "You") and Abblix Limited Liability Partnership ("Copyright Holder") for the OIDC Server ("Software").

**ATTENTION!** Please, thoroughly examine the terms and conditions in this License Agreement before operating the Software. By using the Software, you wholeheartedly and unconditionally agree to the terms set forth in this License Agreement. If any of the terms within this License Agreement are unsuitable, you have no right to use the Software and must promptly uninstall it from your system.

## 1. Definitions
1.1. "Software" refers to the "OIDC Server" software, including any accompanying materials, updates, and extensions, the copyright of which belongs to Abblix Limited Liability Partnership. The Software is certified by the OpenID Foundation ([openid.net/certification](https://openid.net/certification/)). The source code is publicly viewable at [github.com/Abblix/Oidc.Server](https://github.com/Abblix/Oidc.Server) for evaluation purposes, subject to all restrictions in this Agreement. The full text of this Agreement is available at [oidc.abblix.com/license](https://oidc.abblix.com/license).

1.2. "System" refers to an operating system, virtual machine, or equipment, including a server, on which the Software is installed and/or used.

1.3. "User" or "You" refers to a natural or legal person who installs and/or uses the Software on their behalf or legally owns a copy of the Software. If the Software was downloaded or acquired on behalf of a legal entity, the term "User" or "You" refers to the legal entity for which the Software was downloaded or acquired, and is accepting this Agreement through an authorized representative.

1.4. "Partners" refers to organizations that distribute the Software based on agreement with the Copyright Holder.

1.5. "Software Extensions" are additional software components and software solutions provided by the Copyright Holder that extend the functionality of the Software and may require the purchase of a separate license or an extension of an existing license. Software Extensions can be provided both free of charge and paid. You can obtain more detailed information before receiving such extensions.

1.6. "Client" or "Client Application" refers to software programs that interact with the Software (OpenID Connect server) to authenticate users and obtain tokens for accessing protected resources. Each unique client application is identified by a distinct client identifier (client_id) registered with the Software.

1.7. "Issuer" refers to a unique authorization server in a specific environment that authenticates various client applications. Each Issuer, as a separate authorization entity, may span multiple servers in a cluster for load balancing and fault tolerance. Importantly, every server within a single Issuer setup shares a unified Issuer URL, ensuring a consistent and secure identification point for all applications.

1.8. **System Definition for Licensing Purposes.** For purposes of determining license compliance:
   (a) A single physical server or virtual machine (VM) constitutes one System;
   (b) Containerized deployments (Docker containers, Kubernetes pods, or similar technologies) running on a single physical or virtual host are considered part of that single System and do not constitute separate Systems;
   (c) Multiple physical servers or VMs serving one public hostname for load-balancing, high availability, or failure-resistance purposes are considered one System;
   (d) Multiple physical servers or VMs serving different hostnames or independent services constitute multiple Systems;
   (e) Installation limits for commercial licenses vary by license type and are specified in your purchase agreement and at [abblix.com/abblix-oidc-server-pricing](https://www.abblix.com/abblix-oidc-server-pricing).

## 2. License Grant
2.1. You are granted a non-exclusive license to use the Software within the scope of the functionality described on the Copyright Holder's official website, available at [oidc.abblix.com/functionality](https://oidc.abblix.com/functionality), provided that you comply with all restrictions and conditions specified in this License Agreement. This license does not grant sublicensing or redistribution rights to third parties. To obtain sublicensing or redistribution rights, you must purchase a separate type of license.

2.2. You acknowledge that the license granted under clause 2.1 does not include the right to:
   - Distribute, sell, or rent;
   - License, modify, reproduce, translate, adapt, reverse engineer, decompile, or disassemble any part of the Software;
   - Alter the source code of any part of the Software;
   - Remove, obscure, interfere with, or circumvent any feature of the Software, including, but not limited to, copyright or other intellectual property notices, security, or access control mechanisms.

2.3. You may not use the Software in commercial projects, except as provided in clause 2.5. If you wish to use the Software for non-commercial purposes, you may download and access the Software free of charge, subject to all license terms and technical limits specified in Section 2.3.1. Examples of non-commercial projects include:
   - Free educational projects;
   - Games without monetization;
   - Test versions of commercial systems for piloting/demonstrating performance in internal non-commercial environments without generating profit.
In the event that your product uses any types of advertising, paid subscriptions, or any type of commercial component, this software does not permit you to use it on a free basis.

2.3.1. **Non-Commercial License Technical Limits.** Non-commercial licenses granted at no charge are subject to the following technical restrictions enforced by the Software:
   (a) **Client Limit**: Maximum 2 (two) unique client applications may be used;
   (b) **Issuer Limit**: Maximum 1 (one) issuer may be used;
   (c) **Your Responsibility**: You acknowledge and agree that You are solely responsible for monitoring Your usage and ensuring compliance with these limits. Any usage exceeding these limits constitutes a violation of this License Agreement. You must remedy such violations as soon as possible by either: (i) reducing the number of clients or issuers to compliant levels, or (ii) upgrading to a commercial license under Section 2.5 or Section 2.6;
   (d) **Goodwill Grace Period**: The Software allows usage up to 130% of the client limit (3 clients maximum) as a goodwill gesture to avoid disrupting Your operations while You take corrective action. This grace period does not constitute permission to exceed the licensed limits and must not be relied upon for ongoing operations. You remain responsible for eliminating the violation promptly;
   (e) **Technical Enforcement**: The Software tracks client and issuer usage in real-time and logs warnings when limits are approached or exceeded. Authentication requests exceeding 130% of the client limit will be refused to ensure license compliance;
   (f) **Consequences of Non-Compliance**: Failure to remedy violations of these limits may result in termination of Your license under Section 3.5, in addition to any other remedies available to the Copyright Holder under this Agreement or applicable law.

2.4. If the laws of your country prohibit you from using the Software, you are not authorized to use it, and you agree to comply with all applicable laws and regulations concerning your use of the Software.

2.5. If you wish to use the Software in commercial projects, or if your projects have a commercial component in any way, you may download and use the Software during the term upon payment of the applicable license fee, in accordance with the terms of this Agreement.

2.6. **Commercial License Types.** Abblix LLP offers the following commercial license types:

   (a) **Standard License** - For use of the Software in your commercial applications and services. Installation limits and specific terms are defined at the time of purchase.

   (b) **Redistribution License** - Permits redistribution of the Software as part of your commercial products, subject to additional terms and conditions.

   (c) **Pricing and Detailed Terms.** Current pricing, installation limits, and detailed license comparisons are available at:
       - Pricing: [abblix.com/abblix-oidc-server-pricing](https://www.abblix.com/abblix-oidc-server-pricing)
       - License Comparison: [abblix.com/abblix-licenses-support-agreements](https://www.abblix.com/abblix-licenses-support-agreements)

   (d) **Purchase Agreement Controls.** The specific terms of your license (type, installation limits, duration, pricing) are governed by your purchase agreement or order confirmation. In the event of conflict between this License Agreement and your purchase agreement, the purchase agreement shall control with respect to commercial terms.

   (e) **Commercial License Technical Parameters.** Commercial licenses include the following technical parameters enforced by the Software:
      (i) **Client Limit**: The maximum number of client applications permitted, as specified in your purchase agreement;
      (ii) **Issuer Limit**: The maximum number of issuers permitted, as specified in your purchase agreement;
      (iii) **Valid Issuers**: An optional whitelist of specific issuer URLs permitted under the license;
      (iv) **License Period**: Start date (NotBefore), expiration date (ExpiresAt), and optional grace period after expiration;
      (v) **Your Responsibility**: You acknowledge and agree that You are solely responsible for monitoring Your usage and ensuring compliance with the limits specified in your purchase agreement. Any usage exceeding these limits constitutes a violation of this License Agreement. You must remedy such violations as soon as possible by either: (a) reducing the number of clients or issuers to compliant levels, or (b) upgrading to a higher-tier commercial license or purchasing additional capacity;
      (vi) **Goodwill Grace Period**: The Software allows usage up to 130% of your purchased client limit as a goodwill gesture to avoid disrupting Your operations while You take corrective action. This grace period does not constitute permission to exceed the licensed limits and must not be relied upon for ongoing operations. You remain responsible for eliminating the violation promptly;
      (vii) **Technical Enforcement**: The Software tracks client and issuer usage in real-time and logs warnings when limits are approached or exceeded. Authentication requests exceeding 130% of your client limit will be refused to ensure license compliance;
      (viii) **Consequences of Non-Compliance**: Failure to remedy violations of these limits may result in termination of Your license under Section 3.5, in addition to any other remedies available to the Copyright Holder under this Agreement or applicable law.

## 3. Activation and Duration
3.1. When installing the Software, the period of use of the Software is indicated at the time of purchase or upon receipt of the Software free of charge under certain conditions in accordance with Section 2 of this agreement.

3.2. If you obtain the Software from a Partner, the useful life of the Software may be determined between you and the Partner.

3.3. The Software can only be installed on platforms suitable for its use. The Copyright Holder does not provide support for the following situations: copies of the Software installed on platforms not specified on the official website page, available at [oidc.abblix.com/requirements](https://oidc.abblix.com/requirements); support requests not related to the normal use of the Software; or support requests arising from the use of third-party products that either prohibit or do not function with the Software.

3.4. The license period for the Software can be verified on the official website page at [oidc.abblix.com/license-check](https://oidc.abblix.com/license-check).

3.5. If you violate any of the terms of this License Agreement, the Copyright Holder has the right to terminate this License Agreement for the use of the Software immediately or by notifying you 30 calendar days in advance, depending on the severity of the violation. This advance notice is intended to ensure the continuity of your processes and give you the opportunity to correct any actual or alleged misuse or abuse of the Software or any material breach of this Agreement.

3.7. **Software Updates and Maintenance.**

   (a) **Included Updates.** During the active license term, You are entitled to:
      (i) Bug fixes and security patches for the licensed version;
      (ii) Minor version updates (e.g., 1.x to 1.y) within the same major version;
      (iii) Access to updated documentation.

   (b) **Major Version Upgrades.** Upgrades to new major versions (e.g., 1.x to 2.x) may require additional license fees at the Copyright Holder's then-current pricing.

   (c) **End of Life.** The Copyright Holder will provide at least six (6) months' notice before discontinuing support for a major version. Supported versions are listed at [oidc.abblix.com/versions](https://oidc.abblix.com/versions).

3.6. **License Compliance Verification.**

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

4.1. **Library Architecture.** The Software is a library integrated into your applications. It does not transmit data to Abblix LLP or any third parties. All data processing occurs within your infrastructure under your control.

4.2. **License Activation Data.** Abblix LLP collects and processes license activation information (license key, activation date, email address provided during purchase) for the sole purpose of license validation and customer support. This data is retained for the license term plus seven (7) years for legal and accounting purposes, then securely deleted. For data subject rights requests (access, deletion, portability), contact info@abblix.com.

4.3. **Your Compliance Responsibility.** You are solely responsible for ensuring that your use of the Software complies with applicable data protection laws, including GDPR, CCPA, and other privacy regulations in your jurisdiction.

4.4. **Agreement Duration and Termination.** This Agreement shall be in effect for the period specified in the license issued to you upon payment of the applicable license fee for the Software. The Copyright Holder may terminate this Agreement in accordance with the conditions set forth in clause 3.5. You may also terminate this Agreement for any reason by ceasing all use of the Software. Upon termination of this Agreement, no refund will be provided to you, in whole or in part, and you must immediately stop using the Software and provide evidence of such termination to the Copyright Holder upon request.

4.5. **Security Breach Notification.** In the event of a security breach affecting license activation data collected under Section 4.2, the Copyright Holder will:
   (a) Notify You within seventy-two (72) hours of becoming aware of the breach;
   (b) Provide details of the breach, data affected, and remedial measures taken;
   (c) Cooperate with You to meet Your regulatory notification obligations under applicable data protection laws.

## 5. Software Rights
5.1. The Software is wholly owned by the Copyright Holder and is licensed to You, not sold. The Software is protected by copyright laws and international copyright treaties, as well as other intellectual property laws and treaties. Except for the limited rights of use granted herein, all rights, title, and interest in the Software, including patents, copyrights, and trademarks in and to the Software, accompanying printed materials, and any copies of the Software, belong to the Licensor.

## 6. Communications and Notifications

6.1. **Essential Communications.** By using the Software, you agree to receive essential service-related communications from Abblix LLP, including:
   (a) License expiration and renewal notifications;
   (b) Critical security updates and vulnerabilities;
   (c) Important changes to this License Agreement;
   (d) License compliance and activation issues.

6.2. **Promotional Communications (Optional).** You may opt-in to receive promotional materials, product updates, and marketing communications from Abblix LLP and its Partners. You can:
   (a) Opt-out at any time by emailing info@abblix.com with subject "Unsubscribe";
   (b) Use the unsubscribe link provided in each promotional email;
   (c) Withdraw consent without affecting your license rights.

6.3. **Privacy.** Abblix LLP will not sell, rent, or share your email address with third parties for their marketing purposes without your explicit consent.

## 7. Restrictions and Compliance

7.1. You may not rent, lease, or lend the Software.

7.2. For violation of intellectual rights to the software, the violator bears civil, administrative, or criminal liability in accordance with the law.

7.3. You agree that the Software may be used by you only in accordance with its intended use and must not violate local laws.

7.4. **OpenID Foundation Certification.** The Software is certified by the OpenID Foundation, demonstrating conformance to OpenID Connect and OAuth 2.0 specifications. This certification validates the Software's implementation of industry-standard authentication and authorization protocols. Certification details are available at the OpenID Foundation's website.

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

   (c) **GitHub Terms.** Your access to the GitHub repository is subject to GitHub's Terms of Service. Abblix LLP may restrict or revoke repository access at any time.

7.8. **OpenID Foundation Certification.**

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

## 8. Limited Warranty and Disclaimer

8.1. **Limited Warranty (Commercial Licenses Only).** For commercial licenses purchased under Section 2.5 and Section 2.6, the Copyright Holder warrants that, for a period of ninety (90) days from the date of license activation ("Warranty Period"), the Software will substantially conform to the functionality described on the official website at [oidc.abblix.com/functionality](https://oidc.abblix.com/functionality), provided that:
   (a) You use the latest releases of supported versions listed at [oidc.abblix.com/versions](https://oidc.abblix.com/versions);
   (b) The Software is properly installed in accordance with documentation;
   (c) You comply with all terms of this License Agreement.

This limited warranty does NOT apply to non-commercial licenses granted at no charge under Section 2.3 (see Section 8.8 for non-commercial license terms).

8.2. **Exclusive Remedy.** Your exclusive remedy for breach of the limited warranty in Section 8.1 shall be, at the Copyright Holder's sole discretion: (i) repair or replacement of the non-conforming Software; (ii) refund of the license fee paid; or (iii) provision of workarounds or patches to achieve substantial conformity. This remedy is contingent upon You providing written notice of the non-conformity to info@abblix.com within the Warranty Period.

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

8.8. **Non-Commercial License Disclaimer.** For non-commercial licenses granted at no charge under Section 2.3, the Software is provided strictly "AS IS" WITHOUT WARRANTY OF ANY KIND, express or implied. You acknowledge and agree that You use the Software entirely at Your own risk. The limited warranty in Section 8.1 does NOT apply to non-commercial licenses. The liability cap in Section 9.1 ($1,000 USD for non-commercial licenses) applies only to claims that survive this warranty disclaimer under applicable law, such as claims for gross negligence, willful misconduct, or fraud.

## 9. Limitation of Liability

9.1. **Liability Cap.** To the maximum extent permitted by applicable law, the Copyright Holder and/or its partners shall not be liable for any loss and/or damage (including losses due to lost commercial profits, business interruption, loss of information, or other property damage) arising from or in connection with the use or inability to use the software, even if the Copyright Holder and its partners have been notified of the possible occurrence of such losses and/or damage. In any event, the aggregate liability of the Copyright Holder and its partners under any provision of this License Agreement shall not exceed the greater of:
   (a) The total license fees paid by You to the Copyright Holder in the twelve (12) months immediately preceding the event giving rise to liability; or
   (b) Ten Thousand United States Dollars ($10,000 USD).

For non-commercial licenses granted at no charge, the liability cap shall be One Thousand United States Dollars ($1,000 USD).

9.2. **Enforceability.** The limitations set forth in this Section 9 cannot be excluded or limited under applicable law. Some jurisdictions do not allow the limitation or exclusion of liability for incidental or consequential damages, so the above limitation may not apply to you.

## 10. Intellectual Property Rights and Confidentiality

10.1. You agree that the Software, documentation, and all other objects of copyright, systems, ideas, methods of work, and other information contained in the Software, as well as trademarks, are the intellectual property of the Copyright Holder or its Partners. This License Agreement does not grant you any rights to use intellectual property, including trademarks and service marks of the Licensor or its Partners, except for the rights granted by this License Agreement.

10.2. You agree that you will not modify or change the Software in any way. You may not remove or modify any copyright or other proprietary notices on any copy of the Software.

10.3. **Confidentiality.** The Software is confidential and proprietary information. You agree to maintain the confidentiality of the Software and not to disclose any confidential information related to the Software to any third party without the prior written consent of the Copyright Holder.

10.4. **Confidentiality Exceptions.** The confidentiality obligations in Section 10.3 do not apply to information that:
   (a) Was publicly available before disclosure to You;
   (b) Becomes publicly available through no fault of Yours;
   (c) Was independently developed by You without reference to the Software;
   (d) Is required to be disclosed by law, regulation, or court order (provided You give prompt written notice to the Copyright Holder to allow the Copyright Holder to seek protective measures).

## 11. Governing Law and Dispute Resolution

11.1. **Governing Law and Jurisdiction.** This License Agreement is governed by the laws of the Republic of Kazakhstan. Any disputes, controversies, or claims arising out of or relating to this License Agreement, or the breach, termination, or invalidity thereof, shall be subject to the exclusive jurisdiction of the specialized inter-district economic court of Astana city, Republic of Kazakhstan.

11.2. **Language of Proceedings.** Legal proceedings may be conducted in Kazakh, Russian, or English as permitted by applicable procedural rules. Each party bears responsibility for translation costs for documents it submits.

11.3. **Negotiation Before Litigation.** In the event of any dispute, controversy, or claim arising out of or relating to this License Agreement, or the breach, termination, or invalidity thereof, the parties shall first seek to resolve the dispute through good faith negotiations. This process should involve direct communication between the parties or their designated representatives with the aim to reach an amicable settlement. If the dispute cannot be resolved through negotiation within thirty (30) days, then either party may proceed to litigation as described in Section 11.1.

11.4. **Severability.** If any provision of this License Agreement is held to be void, voidable, unenforceable, or illegal, the remaining provisions of this License Agreement will remain in full force and effect. In the event of a conflict between the terms of this Agreement and the terms of any software product license agreement concluded between you and the Partners or the Copyright Holder, the terms of such a license agreement shall prevail; in all other respects, the terms of this Agreement and such agreement shall apply.

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

12.5. **Export Classification.** The Software is classified under ECCN 5D992 (encryption software utilizing standard cryptographic interfaces of widely distributed operating systems). Export from the United States is authorized under License Exception ENC pursuant to 15 CFR § 740.17(b).

## 13. Indemnification

13.1. **Intellectual Property Indemnification.** Subject to the limitations in Section 13.3, the Copyright Holder will defend You against any third-party claim that the Software, when used in accordance with this Agreement, infringes a patent, copyright, or trademark registered in the United States, European Union, or United Kingdom, and will indemnify You from any damages, costs, and attorney fees finally awarded against You by a court of competent jurisdiction or agreed in settlement.

13.2. **Conditions.** The indemnification obligations in Section 13.1 are conditioned upon You:
   (a) Promptly notifying the Copyright Holder in writing of the claim within thirty (30) days of becoming aware;
   (b) Granting the Copyright Holder sole control of the defense and settlement;
   (c) Providing reasonable cooperation in the defense at the Copyright Holder's expense.

13.3. **Limitations.** The Copyright Holder has no obligation to indemnify claims arising from:
   (a) Modification of the Software by You or third parties not authorized by the Copyright Holder;
   (b) Use of the Software in combination with non-Abblix products, data, or services not specified in the documentation;
   (c) Use of superseded or unsupported versions of the Software after being provided with updates;
   (d) Use of the Software in violation of this Agreement or applicable law;
   (e) Compliance with Your specific designs, specifications, or instructions.

13.4. **Remedies.** If the Software is, or in the Copyright Holder's opinion is likely to be, subject to an infringement claim, the Copyright Holder may at its option:
   (a) Procure the right for You to continue using the Software;
   (b) Replace or modify the Software to be non-infringing while maintaining substantially equivalent functionality;
   (c) Terminate the license and refund pro-rata license fees for the unused portion of the prepaid term.

13.5. **Exclusive Remedy.** This Section 13 states the Copyright Holder's entire liability and Your exclusive remedy for intellectual property infringement claims related to the Software.

## 14. Survival

14.1. **Surviving Provisions.** The following sections shall survive termination or expiration of this Agreement: Section 4 (Data Processing and Privacy), Section 5 (Software Rights), Section 9 (Limitation of Liability), Section 10 (Intellectual Property Rights and Confidentiality), Section 11 (Governing Law and Dispute Resolution), Section 13 (Indemnification - for claims arising during the term), and this Section 14 (Survival).

## 15. Contact Information

**Copyright Holder**: Abblix Limited Liability Partnership

**Website**: [abblix.com](https://www.abblix.com)

**Email**: [info@abblix.com](mailto:info@abblix.com)

**Support**: [support@abblix.com](mailto:support@abblix.com)

**Data Protection Officer**: [info@abblix.com](mailto:info@abblix.com)

---

*Last Updated: October 22, 2025*
