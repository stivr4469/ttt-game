import json
import os
from dotenv import load_dotenv
from evidence_client import EvidenceClient
from constants import CONTROLS_MAP_FILE

load_dotenv()

EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")
FRAMEWORK_NAME = "SOC 2 Type II"

CONTROLS_DATA = [
    # CC1 — Control Environment
    {"code": "CC1.1", "title": "Commitment to Integrity and Ethical Values"},
    {"code": "CC1.2", "title": "Board Independence and Oversight of Internal Control"},
    {"code": "CC1.3", "title": "Management Structures, Reporting Lines, Authorities, and Responsibilities"},
    {"code": "CC1.4", "title": "Commitment to Attract, Develop, and Retain Competent Individuals"},
    {"code": "CC1.5", "title": "Accountability for Internal Control Responsibilities"},
    
    # CC2 — Communication and Information
    {"code": "CC2.1", "title": "Use of Relevant, Quality Information"},
    {"code": "CC2.2", "title": "Internal Communication of Objectives and Responsibilities"},
    {"code": "CC2.3", "title": "External Communication on Internal Control Matters"},
    
    # CC3 — Risk Assessment
    {"code": "CC3.1", "title": "Specification of Objectives"},
    {"code": "CC3.2", "title": "Risk Identification and Analysis"},
    {"code": "CC3.3", "title": "Fraud Risk Assessment"},
    {"code": "CC3.4", "title": "Assessment of Changes Affecting Internal Control"},
    
    # CC4 — Monitoring Activities
    {"code": "CC4.1", "title": "Ongoing and Separate Evaluations of Internal Control"},
    {"code": "CC4.2", "title": "Communication of Internal Control Deficiencies"},
    
    # CC5 — Control Activities
    {"code": "CC5.1", "title": "Selection and Development of Control Activities"},
    {"code": "CC5.2", "title": "General Controls over Technology"},
    {"code": "CC5.3", "title": "Deployment of Controls through Policies and Procedures"},
    
    # CC6 — Logical and Physical Access Controls
    {"code": "CC6.1", "title": "Logical Access Security Software and Architectures"},
    {"code": "CC6.2", "title": "Registration and Authorization of New Users"},
    {"code": "CC6.3", "title": "Role-Based Access and Least Privilege"},
    {"code": "CC6.4", "title": "Physical Access Restrictions to Facilities and Protected Assets"},
    {"code": "CC6.5", "title": "Secure Disposal of Physical Assets Containing Sensitive Data"},
    {"code": "CC6.6", "title": "Logical Access — Network Perimeter", "description": "Logical access security measures to protect against threats from sources outside system boundaries"},
    {"code": "CC6.7", "title": "Restriction and Protection of Information During Transmission"},
    {"code": "CC6.8", "title": "Controls to Prevent or Detect Malware on System Components"},
    
    # CC7 — System Operations
    {"code": "CC7.1", "title": "Detection and Monitoring of Configuration Changes and New Vulnerabilities"},
    {"code": "CC7.2", "title": "Monitoring for Anomalies Indicative of Malicious Acts or Errors"},
    {"code": "CC7.3", "title": "Evaluation of Security Events and Incidents"},
    {"code": "CC7.4", "title": "Incident Response Program"},
    {"code": "CC7.5", "title": "Recovery from Security Incidents"},
    
    # CC8 — Change Management
    {"code": "CC8.1", "title": "Authorization, Design, Development, Testing, and Implementation of Changes"},
    
    # CC9 — Risk Mitigation
    {"code": "CC9.1", "title": "Risk Mitigation for Business Disruptions"},
    {"code": "CC9.2", "title": "Assessment and Management of Vendor and Business Partner Risks"}
]

def main():
    client = EvidenceClient(EVIDENCE_TRACKER_URL)
    
    # 1. Find or create framework
    print(f"Checking for framework '{FRAMEWORK_NAME}'...")
    frameworks = client.get_frameworks()
    framework = next((f for f in frameworks if f["name"] == FRAMEWORK_NAME), None)
    
    if not framework:
        print(f"Creating framework '{FRAMEWORK_NAME}'...")
        framework = client.create_framework(FRAMEWORK_NAME, "AICPA Trust Services Criteria (2017)")
    else:
        print(f"Framework '{FRAMEWORK_NAME}' already exists.")
        
    framework_id = framework["id"]
    
    # 2. Create controls if they don't exist
    print(f"Seeding {len(CONTROLS_DATA)} controls...")
    existing_controls = client.get_controls(framework_id)
    controls_map = {}
    created_count = 0
    skipped_count = 0
    
    for ctrl in CONTROLS_DATA:
        existing = next((c for c in existing_controls if c["code"] == ctrl["code"]), None)
        if not existing:
            new_ctrl = client.create_control(
                framework_id=framework_id,
                code=ctrl["code"],
                title=ctrl["title"],
                description=ctrl.get("description", "")
            )
            controls_map[ctrl["code"]] = new_ctrl["id"]
            created_count += 1
        else:
            controls_map[ctrl["code"]] = existing["id"]
            skipped_count += 1
            
    # 3. Save mapping
    with open("controls_map.json", "w") as f:
        json.dump(controls_map, f, indent=4)
        
    print(f"Successfully saved controls_map.json.")
    print(f"Summary: {created_count} created, {skipped_count} already existed.")

if __name__ == "__main__":
    main()
