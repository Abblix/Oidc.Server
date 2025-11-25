# License Agreement

**Effective Date:** Novemver 18, 2025

This License Agreement ("Agreement") is a legal agreement between you (as a person or entity, "You") and Abblix Limited Liability Partnership ("Copyright Holder") for the OIDC Server ("Software").

**ATTENTION!** Please thoroughly examine the terms and conditions in this License Agreement before operating the Software. By using the Software, you agree to be bound by the terms set forth in this License Agreement. If you do not agree to these terms, you have no right to use the Software and must promptly uninstall it from your System.

## 1. Definitions
1.1. **"Software"** refers to the "OIDC Server" software, including any accompanying materials, updates, and extensions, the copyright of which belongs to Abblix Limited Liability Partnership. The Software is certified by the OpenID Foundation ([openid.net/certification](https://openid.net/certification/)). The source code is publicly viewable at [github.com/Abblix/Oidc.Server](https://github.com/Abblix/Oidc.Server) for evaluation purposes, subject to all restrictions in this Agreement. The full text of this Agreement is available at [oidc.abblix.com/license](https://oidc.abblix.com/license). In the event the specified URL becomes unavailable, the full text of this Agreement may be obtained by contacting the Copyright Holder at the addresses specified in Section 16.

1.2. **"System"** refers to an operating system, virtual machine, or equipment, including a server, on which the Software is installed and/or used.

1.3. **"User"** or **"You"** refers to a natural or legal person who installs and/or uses the Software on their behalf or legally owns a copy of the Software. If the Software was downloaded or acquired on behalf of a legal entity, the term "User" or "You" refers to the legal entity for which the Software was downloaded or acquired, and is accepting this Agreement through an authorized representative.

1.4. **"Partners"** refers to organizations that distribute the Software based on agreement with the Copyright Holder.

1.5. **"Software Extensions"** are additional software components and software solutions provided by the Copyright Holder that extend the functionality of the Software and may require the purchase of a separate license or an extension of an existing license. Software Extensions can be provided both free of charge and paid. You can obtain more detailed information before receiving such extensions.

1.6. **"Client"** or **"Client Application"** refers to software programs that interact with the Software (OpenID Connect server) to authenticate users and obtain tokens for accessing protected resources. Each unique client application is identified by a distinct client identifier (client_id) registered with the Software.

1.7. **"Issuer"** refers to an authorization server instance as defined in the OAuth 2.0 specification (RFC 6749) and OpenID Connect Core specification.

1.8. **System Definition for Licensing Purposes.** For purposes of determining license compliance:

   (a) A single physical server or virtual machine (VM) running one instance of the Software with one public hostname constitutes one System;
   
   (b) Containerized deployments (Docker containers, Kubernetes pods, or similar technologies) running on a single physical or virtual host and serving one public hostname are considered part of that single System and do not constitute separate Systems;
   
   (c) Multiple physical servers or VMs serving one public hostname for load-balancing, high availability, or failure-resistance purposes are considered one System;
   
   (d) Multiple instances of the Software serving different hostnames or independent services constitute multiple Systems, regardless of whether they run on the same physical or virtual host or on separate hosts;
   
   (e) Geo-distributed deployments spanning multiple regions or data centers are considered one System if:
   
   (i) all servers serve the same primary public hostname(s) accessible to end users, and
   
   (ii) regional hostnames (if any) exist solely for infrastructure routing, monitoring, or failover purposes.
   
   If regional instances are designed to be independently accessible via distinct public hostnames for normal user operations (even if the primary scenario does not require users to use these additional hostnames), each regional deployment constitutes a separate System;
   
   (f) Non-production environments (development, testing, staging, beta, QA, or similar) used solely for internal development, quality assurance, or pre-production testing are not counted as separate Systems, provided they are not accessible to external end users or used to provide production services. Each production environment constitutes a separate System.

## 2. License Grant
2.1. You are granted a non-exclusive license to use the Software within the scope of the functionality described on the Copyright Holder's official website, available at [oidc.abblix.com/functionality](https://oidc.abblix.com/functionality), provided that you comply with all restrictions and conditions specified in this License Agreement. This license does not grant sublicensing or redistribution rights to third parties. To obtain sublicensing or redistribution rights, you must purchase a separate type of license.

2.2. **Prohibited Actions.** You may not:

   (a) Modify, alter, translate, adapt, or create derivative works from the Software;
   
   (b) Reverse engineer, decompile, or disassemble the Software;
   
   (c) Distribute, sublicense, sell, rent, lease, or lend the Software;
   
   (d) Remove, obscure, or circumvent copyright, proprietary notices, or access controls.

2.3. You may not use the Software in commercial projects, except as provided in Section 2.5. If you wish to use the Software for non-commercial purposes, you may download and access the Software free of charge, subject to all license terms and technical limits specified in Section 2.3.1. Examples of non-commercial projects include:

   (a) Free educational projects;
   
   (b) Games without monetization;
   
   (c) Internal testing or evaluation of the Software before purchasing a commercial license, provided such use does not occur in production environments and does not generate revenue.

If your product generates revenue through advertising, paid subscriptions, or any commercial means, you may not use the Software under the free non-commercial license.

2.3.1. **Non-Commercial License Technical Limits.** Non-commercial licenses granted at no charge are subject to the following technical restrictions:

   (a) **Client Limit**: Maximum **2 (two)** unique client applications may be used;
   
   (b) **Issuer Limit**: Maximum **1 (one)** issuer may be used;
   
   (c) **Enforcement**: These limits are enforced according to the License Limit Enforcement Framework specified in Section 2.7. Violations must be remedied by either:
   
   (i) reducing the number of clients or issuers to compliant levels, or
   
   (ii) upgrading to a commercial license under Section 2.5 or Section 2.6.

2.4. If the laws of your country prohibit you from using the Software, you are not authorized to use it, and you agree to comply with all applicable laws and regulations concerning your use of the Software.

2.5. If you wish to use the Software in commercial projects, or if your projects have a commercial component in any way, you may download and use the Software during the term upon payment of the applicable license fee, in accordance with the terms of this Agreement.

2.6. **Commercial Licenses.** Commercial license types (Standard, Redistribution) are available for commercial use. Current pricing, terms, and license comparisons are available at [abblix.com/abblix-oidc-server-pricing](https://www.abblix.com/abblix-oidc-server-pricing). The specific terms of your license are governed by your purchase agreement. In the event of conflict between this License Agreement and your purchase agreement, the purchase agreement shall control.

2.7. **License Enforcement.** You are solely responsible for monitoring your usage and ensuring compliance with license limits. The Software may enforce limits through technical means, including warnings, feature restrictions, or denial of service. Failure to comply may result in termination under Section 3.5.

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
   
   (iv) Violation of intellectual property rights specified in Section 10.

   (b) **Termination with Notice.** For all other breaches, the Copyright Holder shall provide **thirty (30) days'** written notice (as defined in Section 11.6) specifying the breach. You shall have **thirty (30) days** from receipt of notice to cure the breach. If the breach is not cured within this period, the Copyright Holder may terminate this Agreement upon expiration of the cure period.

   (c) **Effect of Termination.** Upon termination, You must immediately cease all use of the Software, uninstall all copies, and certify destruction in writing to the Copyright Holder within **ten (10) days**.

3.6. **License Keys.** All license keys are generated exclusively by the Copyright Holder and cannot be self-generated, transferred, or modified. You are responsible for maintaining the confidentiality of your license keys. License keys expire on the date specified; renewal requires explicit request to the Copyright Holder.

3.7. **Software Updates.** Updates and maintenance terms for commercial licenses are specified in your purchase agreement. Free License users receive the Software "as is" without any commitment to updates, support, or maintenance.

## 4. Data Processing

4.1. **Library Architecture.** The Software is a library integrated into your applications. It does not transmit data to the Copyright Holder or any third parties. All data processing occurs within your infrastructure under your control.

4.2. **Data Protection.** The Copyright Holder is not a Data Processor under GDPR, CCPA, or similar data protection laws. You act as the Data Controller and are solely responsible for compliance with all applicable data protection regulations.

## 5. Software Rights
5.1. The Software is wholly owned by the Copyright Holder and is licensed to You, not sold. The Software is protected by copyright laws and international copyright treaties, as well as other intellectual property laws and treaties. Except for the limited rights of use granted herein, all rights, title, and interest in the Software, including patents, copyrights, and trademarks in and to the Software, accompanying printed materials, and any copies of the Software, belong to the Copyright Holder.

## 6. Notifications

6.1. Important notifications regarding the Software, including security updates, license changes, and version information, are published on the official website at [abblix.com](https://www.abblix.com), in the documentation at [docs.abblix.com](https://docs.abblix.com), and the GitHub repository at [github.com/Abblix/Oidc.Server](https://github.com/Abblix/Oidc.Server).

## 7. Source Code and Certifications

7.1. **Source Code Transparency.** The Software source code is publicly available at [github.com/Abblix/Oidc.Server](https://github.com/Abblix/Oidc.Server) to enable security audits and technical evaluation. Public availability does NOT constitute open-source licensing. The Software remains subject to all restrictions in this Agreement.

7.2. **Certifications and Standards.** Implemented standards and certifications are documented at [docs.abblix.com/docs/implemented-standards](https://docs.abblix.com/docs/implemented-standards). The Copyright Holder does not claim any certifications beyond those explicitly documented.

## 8. Warranty Disclaimer

8.1. **Free Licenses.** For free licenses under Section 2.3, the Software is provided "AS IS" WITHOUT WARRANTY OF ANY KIND. You use the Software entirely at your own risk.

8.2. **Commercial Licenses.** For commercial licenses, the Copyright Holder warrants that the Software implements the standards documented at [docs.abblix.com/docs/implemented-standards](https://docs.abblix.com/docs/implemented-standards). No other warranties are provided.

8.3. **DISCLAIMER.** TO THE MAXIMUM EXTENT PERMITTED BY THE LAW GOVERNING THIS AGREEMENT, THE COPYRIGHT HOLDER DISCLAIMS ALL OTHER WARRANTIES, WHETHER EXPRESS, IMPLIED, OR STATUTORY, INCLUDING WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

8.4. **Mandatory Rights.** Nothing in this Agreement excludes rights that cannot be lawfully excluded under the law governing this Agreement.

## 9. Limitation of Liability

9.1. **Liability Cap.** To the maximum extent permitted by the law governing this Agreement, the Copyright Holder shall not be liable for any indirect, incidental, special, consequential, or punitive damages, including loss of profits, data, business opportunities, or other property damage, arising from or in connection with the use or inability to use the Software.

For commercial licenses, the aggregate liability of the Copyright Holder under any provision of this License Agreement shall not exceed the license fees paid by You for the most recent license term.

For non-commercial licenses granted at no charge, the Copyright Holder shall have no liability whatsoever.

9.2. **Enforceability.** The limitations set forth in this Section 9 shall apply to the fullest extent permitted by applicable law. Some jurisdictions do not allow the limitation or exclusion of liability for incidental or consequential damages; in such jurisdictions, the above limitation may not apply to You, and the Copyright Holder's liability shall be limited to the maximum extent permitted by applicable law.

## 10. Intellectual Property Rights and Confidentiality

10.1. You agree that the Software, documentation, and all other objects of copyright, systems, ideas, methods of work, and other information contained in the Software, as well as trademarks, are the intellectual property of the Copyright Holder or its Partners. This License Agreement does not grant you any rights to use intellectual property, including trademarks and service marks of the Copyright Holder or its Partners, except for the rights granted by this License Agreement.

10.2. **Confidentiality.** Confidential information includes license keys, non-public documentation, pricing terms, and any other information not publicly available. You agree to maintain confidentiality of such information and not disclose it to third parties without prior written consent of the Copyright Holder. This obligation does not apply to information required to be disclosed by law or court order.

## 11. Governing Law and Dispute Resolution

11.1. **Governing Law and Jurisdiction.** This License Agreement is governed by the laws of the Republic of Kazakhstan. Any disputes shall be subject to the exclusive jurisdiction of the courts of Astana, Republic of Kazakhstan.

At the Licensee's option, exercised by written notice to the Copyright Holder prior to any dispute arising, the Licensee may elect to have this Agreement governed by the acting law of the Astana International Financial Centre (AIFC), with disputes subject to the exclusive jurisdiction of the AIFC Court.

11.2. **Negotiation Before Litigation.** In the event of any dispute, controversy, or claim arising out of or relating to this License Agreement, or the breach, termination, or invalidity thereof, the parties shall first seek to resolve the dispute through good faith negotiations. This process should involve direct communication between the parties or their designated representatives with the aim to reach an amicable settlement. If the dispute cannot be resolved through negotiation within **thirty (30) days**, then either party may proceed to litigation as described in Section 11.1.

11.3. **Severability.** If any provision of this License Agreement is held to be void, voidable, unenforceable, or illegal, the remaining provisions of this License Agreement will remain in full force and effect. In the event of a conflict between the terms of this Agreement and the terms of any software product license agreement concluded between you and the Partners or the Copyright Holder, the terms of such a license agreement shall prevail; in all other respects, the terms of this Agreement and such agreement shall apply.

11.4. **External Document Conflicts.** In the event of a conflict between the terms of this License Agreement and information provided on external websites (including but not limited to oidc.abblix.com, GitHub repositories, or third-party documentation):

   (a) This License Agreement shall prevail for all legal rights, obligations, warranties, and limitations of liability;
   
   (b) External website content is provided for informational and technical reference purposes only;
   
   (c) You acknowledge that external content may be updated without notice and does not modify the terms of this Agreement unless explicitly incorporated by reference;
   
   (d) Any discrepancies should be reported to info@abblix.com for clarification.

11.5. **Entire Agreement.** This Agreement, together with any purchase agreement or order confirmation referencing this Agreement, constitutes the entire agreement between You and the Copyright Holder regarding the Software and supersedes all prior or contemporaneous understandings, agreements, representations, and warranties, whether written or oral, regarding such subject matter. This Agreement may be modified only by a written amendment signed by authorized representatives of both parties. No provision of this Agreement may be waived except by a writing signed by the party against whom the waiver is sought to be enforced.

11.6. **Notices.** All notices required under this Agreement must be in writing and shall be deemed given when:

   (a) delivered personally;
   
   (b) sent by confirmed email to the addresses specified in Section 16 (Contact Information); or
   
   (c) **three (3) business days** after deposit with an internationally recognized courier service with tracking capability.
   
   Either party may update its notice address by providing written notice to the other party in accordance with this section.

## 12. Intellectual Property Claims

12.1. If You receive a third-party claim that the Software infringes intellectual property rights, the Copyright Holder will provide reasonable documentary and technical support for Your defense, including ownership documentation and technical evidence.

12.2. You must promptly notify the Copyright Holder of any such claim within **thirty (30) days**. The Copyright Holder assumes no financial responsibility for defense costs, damages, or settlements.

12.3. If the Software is subject to a valid infringement claim, the Copyright Holder may at its option:

   (a) procure the right for You to continue using the Software;
   
   (b) modify the Software to be non-infringing; or
   
   (c) terminate the license and refund pro-rata fees for the unused term (commercial licenses only).

## 13. Force Majeure

13.1. The Copyright Holder shall not be liable for any failure or delay in providing updates, support, or other services due to causes beyond its reasonable control, including war, terrorism, civil unrest, strikes, government actions, epidemics, pandemics, natural disasters, or telecommunications failures.

13.2. If such event continues for more than **ninety (90) days**, You may terminate this Agreement upon written notice. The Copyright Holder shall refund pro-rata license fees for the unused portion of the prepaid term (commercial licenses only).

## 14. Assignment

You may not assign this Agreement without prior written consent of the Copyright Holder, except in connection with a merger, acquisition, or sale of substantially all assets, provided You notify the Copyright Holder within **thirty (30) days**.

## 15. Survival

The following sections shall survive termination or expiration of this Agreement: Section 5 (Software Rights), Section 9 (Limitation of Liability), Section 10 (Intellectual Property Rights and Confidentiality), Section 11 (Governing Law and Dispute Resolution), and this Section 15 (Survival).

## 16. Contact Information

**Copyright Holder**: Abblix Limited Liability Partnership

**Website**: [abblix.com](https://www.abblix.com)

**Email**: [info@abblix.com](mailto:info@abblix.com)

**Support**: [support@abblix.com](mailto:support@abblix.com)
