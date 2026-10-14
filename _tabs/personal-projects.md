---
icon: fas fa-laptop-code
order: 5
---

## Academic Projects

<section class="portfolio-card" markdown="1">

### Orchestryx

**Cyber Range as a Service · Cloud-Native Cybersecurity Lab Platform**

<img class="portfolio-image portfolio-image--project" src="/assets/img/projects/orchestryx-lab-catalog.png" alt="Orchestryx lab catalog displaying available cybersecurity practice environments">

Orchestryx is an academic project exploring how to make realistic cybersecurity practice environments easier to access. The platform is designed to let users browse pre-built lab templates and request isolated, temporary environments through a web application, with the goal of making hands-on security learning more reproducible and accessible.

The project brings together a web interface and cloud-based control plane for user accounts, lab catalog and lifecycle management, and asynchronous task processing. Its AWS architecture uses **Amazon Cognito, ECS on Fargate, AWS CDK, Aurora Serverless, Amazon SQS, AWS Secrets Manager, and Amazon CloudWatch**. The lab design includes containerized vulnerable targets, dedicated VPC networking, and secure WireGuard VPN access, with teardown planned to remove session resources and support isolation and cost control.

The current MVP focuses on pre-built labs and the platform foundation; the lab runtime and custom topology and user-supplied Docker workload features remain future development.

**Technologies:** Python, FastAPI, Celery, Next.js, PostgreSQL, AWS

</section>

<section class="portfolio-card" markdown="1">

### OWASP Juice Shop Penetration Test

**Academic Team Project · March 2026**

<img class="portfolio-image portfolio-image--project" src="/assets/img/projects/owasp-juice-shop-assessment.jpg" alt="OWASP Juice Shop application during the penetration testing assessment">

As part of our cybersecurity studies, my teammate **Wejdene Cherif** and I conducted a penetration testing assessment of **OWASP Juice Shop**, a deliberately vulnerable web application designed for security training. We tested it in an isolated Docker lab, using Burp Suite and FoxyProxy to inspect application traffic and carrying out manual and automated tests.

The assessment documented **9 vulnerabilities: 4 Critical and 5 High**, including a demonstrated attack path from unauthenticated access to administrator account compromise. Our report includes evidence, CVSS-based risk ratings, proof-of-concept findings, and practical remediation recommendations aligned with OWASP and NIST guidance.

[Download the full penetration testing report (PDF)](/assets/downloads/owasp-juice-shop-penetration-testing-report.pdf)

</section>
