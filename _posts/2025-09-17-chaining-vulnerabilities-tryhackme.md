---
layout: post
title: "Chaining Vulnerabilities: TryHackMe Walkthrough"
date: 2025-09-17 22:53:56 +0000
categories: [Writeups, TryHackMe]
tags: [vulnerability-chaining, web-security, xss, csrf, authentication, security-testing]
description: "A TryHackMe walkthrough on vulnerability chaining, combining low-to-medium severity issues into a larger application-security impact."
excerpt: "Explore how weak test credentials, stored XSS, and missing CSRF protections can combine into an account-takeover risk—and how to report the full chain."
---

> This walkthrough describes an authorized TryHackMe lab. Test only in the room or in systems for which you have explicit permission. The credential-changing browser script from the original lab is intentionally described rather than reproduced as executable code.

## 1. Introduction

**Vulnerability chaining** is the idea that one weakness may have limited impact on its own, but can become much more serious when combined with other weaknesses. Real-world attackers do not need every individual finding to be critical; several low- or medium-risk issues can provide a path to a significant compromise.

Risk ratings are often assigned to each vulnerability in isolation. Organizations may prioritize critical and high findings while deferring medium and low findings. That can be misleading: verbose error messages or a weak password policy may appear modest in isolation, but when combined with missing CSRF protection or XSS, they can lead to a much more damaging outcome.

This room explores how to assess an application holistically, identify useful relationships between findings, and understand how an attacker might build access step by step.

### Objectives

By the end of the room, you should be able to:

- **Think like an attacker:** Treat small findings as possible stepping stones.
- **Understand common chains:** Recognize why certain weaknesses combine.
- **Recognize weak boundaries:** Identify where trust breaks down between parts of a web application.
- **Follow a chain:** Understand how multiple low- to medium-severity issues can contribute to a larger impact.

> **Answer:** No answer needed.

## 2. Chaining Vulnerabilities

### What is vulnerability chaining?

Vulnerability chaining combines two or more weaknesses to cause more harm than any one could cause alone. One issue may provide an initial foothold, another may expose a sensitive function, and a further weakness may allow access to data or privileged actions.

Consider a **self-XSS** issue in a user-profile editor: the payload only executes in the user's own browser, so its standalone impact is limited. If the application also lacks CSRF protection, an attacker may be able to cause an authenticated victim to save attacker-controlled profile content. If an administrator later views that profile, the stored content can execute in the administrator's browser. The combination changes the impact of both findings.

The key idea is not that every finding is critical on its own; it is that weaknesses can connect to form a more impactful path.

### Why this matters in the real world

The 2019 Capital One breach is a well-known example of a chain involving **server-side request forgery (SSRF)**. SSRF allowed requests from a server to reach the AWS EC2 metadata service. Credentials obtained from that service were then used to access data stored in S3. The impact came from how the issues and permissions combined.

Another common pattern is an application with SQL injection behind a login. If the login process reveals whether a username exists and has no effective attempt limits, those weaknesses may help an attacker discover an account and guess its password. Once authenticated, the attacker may reach the SQL injection issue and access data or privileges.

### Why patch-by-patch fixes are not enough

Teams sometimes patch a SQL injection flaw but leave account enumeration in place, or fix an unsafe upload while leaving XSS that can abuse related workflows. Individual fixes may close one path without addressing the connections among weaknesses.

Security assessment should therefore be **holistic**. Attackers look for combinations of flaws that lead to a goal, whether that goal is access, persistence, or data exposure. Reports should explain how findings interact and recommend fixes that break the chain.

> **Answer:** No answer needed.

## 3. Methodology

### How to think like an attacker

A skilled tester rarely finds one issue and immediately reaches the goal. Instead, they explore the application, identify weaknesses, and consider how those weaknesses interact.

**Step 1: Use the application like a normal user**

Explore the application before testing for vulnerabilities. Register an account, log in, and understand the user flows, roles, and sensitive actions, such as account settings, administrative features, and uploads.

**Step 2: Enumerate and find weaknesses**

Look for familiar vulnerability classes such as SQL injection, XSS, and IDOR, as well as less obvious signals: inconsistent error messages, predictable user IDs in URLs, or unexpectedly accepted file types. Record findings even when their individual risk seems low.

**Step 3: Understand what each finding enables**

Assess each weakness in isolation:

- Does the XSS execute in a useful context?
- Can a verbose login response help identify valid usernames?
- Does a file-upload behavior create an unintended path to execute or serve content?

The goal is to understand the standalone potential of each issue.

**Step 4: Define the likely objective**

Ask what an attacker might want to achieve in this application: access sensitive data, reach an administrative function, or execute code. Context matters; the impact of XSS on a public blog may differ from its impact on a banking dashboard.

**Step 5: Build a path from findings to the objective**

Connect findings into a logical sequence. For example:

> Verbose login responses → identify valid usernames → weak password policy → authenticate → stored XSS → administrator views the affected page → unauthorized administrative action

Document each dependency and the conditions needed for the next step.

**Step 6: Execute and validate each step**

In the authorized lab, verify each step rather than assuming it will work. Confirm whether the authentication weakness is present, whether the XSS executes in the relevant context, and whether the resulting action is possible. Note controls that block or limit the chain, such as rate limits or contextual output encoding.

**Step 7: Report the full chain**

Do not report the bugs as unrelated findings. Explain the path from the initial attacker capability to the final impact, and show how individually lower-severity findings combine into a higher-impact outcome.

> **Answer:** No answer needed.

## 4. Guided Chain

This task demonstrates how several small weaknesses can combine. The example below is limited to the TryHackMe challenge environment.

### Step 1: Developer test credentials

The application at `http://MACHINE_IP/` contained a developer test account:

- **Username:** `testuser`
- **Password:** `password123`

Logging in as this low-privileged account exposed basic user features. Test credentials left active in an application can provide an initial foothold.

### Step 2: Stored XSS in the user profile

The profile editor's **display name** field reflected user input without adequate sanitization. A simple harmless test, such as `<script>alert(1)</script>`, demonstrated script execution when the profile was viewed.

This established the XSS issue. The next question was how the issue could affect another user, such as an administrator who might review the profile.

### Step 3: XSS and missing CSRF protection

The lab application did not implement CSRF tokens. In that context, stored XSS could cause a victim's authenticated browser to submit an application request. Because the browser automatically attaches the victim's session cookies to same-origin requests, the application could mistake the request for an intentional action by that victim.

The original lab used this behavior to change an administrator's account details. The browser-side credential-changing script is not included here; the security lesson is that **stored XSS plus missing CSRF defenses can enable unauthorized actions as the affected user**.

For the lab, the demonstration involved hosting a script and causing the administrator's browser to load it when viewing the affected profile. This sequence illustrates why output encoding and CSRF defenses are complementary: either issue alone can be serious, but their combination may significantly increase impact.

### Step 4: Administrator impact

After the administrator's account was changed in the lab, the challenge allowed the student to sign in as that administrator and access administrative functionality. The access was not obtained by guessing the administrator's password; it resulted from combining the test account, stored XSS, and missing CSRF protection.

### Why each step worked

Each stage depended on an assumption that was not enforced:

- The application assumed developer test accounts would not remain active.
- It trusted profile input without safe output handling.
- It treated authenticated browser requests as legitimate without CSRF protection.
- It relied on account authentication alone to protect sensitive functions.

Together, these weaknesses created a path from a low-privileged account to administrative impact.

> **Question:** What is the flag in the admin panel?  
> **Answer:** `THM{57648b8e-3382-47bb-abbc-f125e128f8ab}`

> **Question:** What vulnerability enabled the attacker to force a change in the admin user's password?  
> **Answer:** Cross-Site Scripting

## 5. Alternate Paths

Vulnerability chains rarely follow a perfectly straight line. A planned step may fail because a defense is in place or the environment behaves differently. A tester should consider alternate paths without exceeding the authorized scope.

### When the chain isn't linear

The guided chain followed this path:

> Test account → XSS → missing CSRF protection → unauthorized account change → administrator access

If CSRF tokens had been present, the attempted account change might have failed. That would not make the XSS irrelevant; it would change what should be assessed next. In an authorized test, consider what data or actions the XSS can access in context, whether sensitive information is exposed, and whether other application controls limit the impact.

Think in terms of pivot points and dependencies. If one step is blocked, determine whether another in-scope path exists. For example, SQL injection that cannot bypass authentication may still expose data that helps demonstrate a separate risk. Map alternatives as findings emerge so the assessment remains structured.

### Red team vs. bug bounty: different endgames

The objective affects how far a chain should be taken.

On a **red-team engagement**, the goal may be to demonstrate organizational impact while following the rules of engagement. This may involve tracing the route to internal systems or sensitive data, but testing should stop at the agreed objective and boundaries.

In a **bug bounty**, the goal is to demonstrate risk clearly so the organization can remediate it. It may be enough to show that an administrator's email could be changed or that a limited data sample could be accessed. Continuing to exploit beyond the proof needed can create unnecessary risk.

Understanding the difference helps determine how much evidence is appropriate. Vulnerability chaining relies on context, observation, and adaptability—not on following a fixed sequence regardless of the target's behavior.

> **Answer:** No answer needed.

## 6. Conclusion

Weaknesses that appear low-risk individually can combine into serious impact. In this walkthrough, a test account, stored XSS, and missing CSRF protection formed a path from a low-privileged account to administrative compromise.

Vulnerability chaining is about context, observation, and understanding what each step enables. Professional penetration-test and red-team reports should explain how weaknesses combine, not only list their isolated severity ratings. That helps defenders prioritize fixes that break the chain and reduce overall risk.

As you work through other rooms, look beyond the critical finding. Consider how smaller issues fit together, validate the full path safely, and document the dependencies and impact.

> **Answer:** No answer needed.

---

*Originally published on [Medium](https://medium.com/@maram.raboudi/chaining-vulnerabilities-tryhackme-f6205fa3a44f).*
