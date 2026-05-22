## Corporate Governance and Board Oversight Policy

### 1. Purpose
The purpose of this Corporate Governance and Board Oversight Policy (the "Policy") is to establish a robust framework for the governance of Marineso. This Policy ensures that the Board of Directors (the "Board") demonstrates independence from management and exercises diligent oversight of the development, implementation, and performance of Marineso’s internal control environment. This framework is specifically designed to meet the requirements of the AICPA Trust Services Criteria, specifically Common Criteria 1.2 (CC1.2), ensuring that the security, availability, processing integrity, confidentiality, and privacy of Marineso's systems are maintained at the highest standards.

### 2. Scope
This Policy applies to all members of the Marineso Board of Directors, executive leadership including the Chief Executive Officer (CEO), Chief Technology Officer (CTO), and Chief Information Security Officer (CISO), as well as all personnel involved in compliance, legal, and internal audit functions. The scope encompasses all governance activities related to the Marineso technological ecosystem, including but not limited to:
- The `stivr4469/compliance-sandbox` GitHub repository for policy and infrastructure-as-code management.
- Identity and access management via the Okta production instance (`trial-7222443.okta.com`).
- Cloud infrastructure operations within AWS (us-east-1), utilizing LocalStack for pre-production validation and simulation.
- Real-time monitoring and reporting via the Marineso Compliance Dashboard (`http://localhost:8000`).

### 3. Definitions
- **Board of Directors (The Board)**: The primary governing body of Marineso responsible for strategic oversight.
- **Independent Director**: A member of the Board who does not have a material relationship with Marineso, either directly or as a partner, shareholder, or officer of an organization that has a relationship with the company.
- **Internal Control Environment**: The set of standards, processes, and structures that provide the basis for carrying out internal control across the organization.
- **LocalStack**: A cloud service emulator used by Marineso to test and validate AWS infrastructure changes in a sandboxed environment before deployment to the `us-east-1` production region.

### 4. Policy Statement
Marineso is committed to a governance model that prioritizes accountability and independence. The Board of Directors serves as the ultimate authority for overseeing risk management and the effectiveness of internal controls.

#### 4.1 Board Independence and Expertise
The Board shall maintain a structure that ensures independence from management. This is achieved by:
- Ensuring that at least one member of the Board is an "Independent Director" with no material relationship with the company.
- Requiring all directors to provide an annual Conflict of Interest disclosure, which is tracked within the `stivr4469/compliance-sandbox` administrative documentation.
- Ensuring the Board possesses sufficient collective knowledge of cybersecurity and SOC 2 compliance requirements to provide effective oversight. The Board may engage external advisors to supplement this expertise as needed.

#### 4.2 Oversight of Internal Control Performance
The Board, primarily through its Audit and Compliance Committee, is responsible for:
- Reviewing the design and operating effectiveness of the internal control system.
- Approving the annual risk assessment and ensuring that management addresses identified vulnerabilities.
- Overseeing the remediation of any control failures (e.g., findings where status is "FAIL" on the Compliance Dashboard).

### 5. Responsibilities
- **The Board of Directors**: Responsible for defining the company’s risk appetite and providing high-level oversight of the SOC 2 compliance program.
- **Executive Management (CEO/CTO)**: Responsible for the day-to-day execution of the Board's strategic directives and ensuring that the compliance team has the necessary tools (Okta, AWS, Slack) to perform their duties.
- **Compliance Officer**: Serves as the primary liaison between management and the Board. Responsible for maintaining the Compliance Dashboard (`http://localhost:8000`) and ensuring the accuracy of evidence.
- **Security & DevOps Teams**: Responsible for the technical implementation of controls and ensuring that automated alerts are correctly routed to the `#compliance-alerts` Slack channel.

### 6. Procedures
#### 6.1 Regular Compliance Reporting
The Compliance Officer shall provide a quarterly "State of Compliance" report to the Board. This report must include:
- A snapshot of the Marineso Compliance Dashboard (`http://localhost:8000`).
- Status updates on all 33 SOC 2 Common Criteria.
- A summary of any violations or failed controls identified by the automated scanner.

#### 6.2 Identity Governance Oversight
The Board shall oversee identity governance by reviewing quarterly access reports generated from Okta (`trial-7222443.okta.com`). This review ensures that administrative privileges are granted based on the principle of least privilege and that terminated employees are promptly deprovisioned.

#### 6.3 Incident Escalation and Communication
In the event of a critical security incident or a material failure of an internal control, the following escalation path must be followed:
1. Immediate notification via the `#compliance-alerts` Slack channel.
2. A technical post-mortem stored in the `stivr4469/compliance-sandbox` repository.
3. A formal briefing to the Board within 72 hours if the incident impacts customer data or system availability.

#### 6.4 Infrastructure and Configuration Oversight
All infrastructure changes in the AWS (us-east-1) environment must be governed by the change management procedures defined in the `stivr4469/compliance-sandbox` repository. The Board reviews the results of annual external audits to ensure these procedures are followed consistently. Changes validated in LocalStack must be formally approved before promotion to the production environment.

### 7. Evidence for Audit
To demonstrate compliance with CC1.2, Marineso shall maintain the following records for at least 12 months:
- Minutes of Board meetings where internal controls or SOC 2 reports were discussed.
- Annual Conflict of Interest forms for all Board members.
- Quarterly snapshots of the Compliance Dashboard (`http://localhost:8000`).
- Logs of Slack `#compliance-alerts` indicating timely response to system-identified failures.

### 8. Enforcement
Compliance with this Policy is mandatory. The Board has the authority to:
- Conduct independent investigations into governance or control failures.
- Require management to implement immediate remediation plans for any "FAIL" status controls.
- Adjust executive compensation based on the achievement of compliance and security objectives.

### 9. Review Cycle
This Corporate Governance and Board Oversight Policy shall be reviewed, updated, and re-approved by the Board of Directors at least annually. More frequent reviews may be triggered by significant changes to the Marineso technical architecture, such as a full migration from LocalStack to AWS production services, or changes in the regulatory landscape.

---
**Approval Block**
- **Approved by**: Board of Directors
- **Date of Approval**: 2026-05-22
- **Version**: 1.0.0
- **Location**: `stivr4469/compliance-sandbox/policies/corporate_governance_policy.md`
