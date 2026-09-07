---
title: "The Art of Protecting Secrets"
date: 2026-09-07 22:00:00 +0100
categories: [Cybersecurity]
tags: [secrets-management, information-security, cryptography, devsecops]
---


I recently came across the term **“the art of protecting secrets.”** It honestly made me pause for a moment.

Many people might immediately associate it with cryptography, but the concept goes far beyond that.

I started digging into it and reading security research. The more I looked, the more I realized that protecting a secret is much more than hiding a password or putting an **API key** inside an **`.env` file**.

**A secret can travel further than you think.**

You can accidentally put it in your source code, commit it to Git, leave it buried in Git history, expose it through CI/CD logs, copy it into a Docker image, send it through a chat, or leave it sitting on a developer's machine.

*Removing it later does not necessarily mean it is gone.*

This is not just a theoretical problem.

![Protecting secrets across a modern infrastructure](/assets/img/articles/secrets/secrets.png)


According to GitGuardian's 2026 research, **28.65 million new hardcoded secrets were added to GitHub commits in 2025**, representing a **34% increase** from the previous year. Even more concerning, *many leaked credentials remain valid long after their initial exposure.*

That changed the way I think about secrets.

So whether you're **developing applications, working with Git, building CI/CD pipelines, or doing cybersecurity**, here are the concepts I believe you should remember.

## 1. Never Hardcode Secrets

Aha! This is probably the most important rule.

Don't write:

```python
API_KEY = "sk-xxxxxxxxxxxxxxxx"
DB_PASSWORD = "MySuperPassword123"
```

It might work perfectly on your machine.

The problem starts when that code gets committed, shared, pushed to GitHub, or copied somewhere else.

Instead, use **environment variables** or, preferably, dedicated **secret managers**.

Remember:

> **A private repository does not mean a secure repository.**

A secret stored in a repository can still be exposed through a compromised account, a leaked token, a careless developer, a fork, a backup, or a misconfigured CI/CD system.

## 2. Understand Where Your Secret Can Go

This is where secret protection becomes interesting.

Now we're talking!

When a secret enters your development environment, ask yourself:

**Where could a copy of this exist?**

It might end up in:

* Source code
* Git history
* Forks
* Developer machines
* CI/CD systems
* Logs
* Docker images
* Backups
* Caches

You don't need to be paranoid.

You just need to understand how data moves through your development environment.

A secret doesn't have to be intentionally exposed to become a security problem. Sometimes, it simply follows the path of the systems and tools that handle it.

## 3. Follow the Principle of Least Privilege

Of course, if you study cybersecurity, this term will hunt you everywhere.

Because not every application needs administrator access.

If your application only needs to read a database, give it a credential that can *read* — not one that can modify or delete everything.

The same applies to cloud accounts, APIs, Kubernetes, GitHub tokens, and basically everything else.

A useful question is:

**If this secret gets stolen today, what can the attacker do with it?**

If the answer is **“everything,”** you probably gave that secret too much power.

The goal isn't only to prevent secrets from being stolen. It's also to **limit the damage when prevention fails**.

## 4. Rotate Your Secrets

This might seem a little confusing at first, so stick with me for a moment!

One of the biggest mistakes is treating a secret as something **permanent**.

A credential should have a **lifecycle**:

> **It is created, used, rotated, and eventually expired or revoked.**

If an API key is exposed, don't simply delete it from the repository.

**Revoke it.**

Then generate a new one.

This is especially important because removing a secret from your source code does not invalidate the secret itself.

Think about it this way:

**Deleting the evidence is not the same as disabling the credential.**

If the secret is still valid, an attacker who already obtained it may still be able to use it.

## 5. Don't Put Secrets in Logs

Debugging can create another security problem, and trust me, it happens more often than you might think.

For example:

```python
print(f"Connecting with: {API_KEY}")
```

It might look harmless during development.

But that API key could end up stored in your application's logs, monitoring systems, centralized logging platforms, or SIEM.

And now you have another copy of your secret somewhere else.

Before logging something, ask yourself:

**Would I be comfortable seeing this value in a public GitHub issue tomorrow?**

If the answer is no, don't log it.

Debugging is useful, but **debugging information can become security information**.

## 6. Treat Git History as Permanent

Deleting a secret from the latest version of a file doesn't necessarily remove it from Git history.

You might initially commit:

```python
API_KEY = "SECRET123"
```

and later change it to:

```python
API_KEY = ""
```

The current version is clean, but the previous commit may still contain **`SECRET123`**.

This is why removing a secret from code and revoking a secret are two **different things**.

If a real credential has been committed, assume it is compromised and rotate it.

Even if you remove the secret from the latest commit, you should consider where else that information may still exist: previous commits, forks, clones, caches, backups, or logs.

## 7. Use Automation, Not Memory

Developers make mistakes.

That's normal.

The solution isn't to expect everyone to remember every security rule.

Use automated controls such as:

* **Secret scanning** to detect credentials already present in repositories.
* **Git pre-commit hooks** to catch secrets before they're committed.
* **GitHub/GitLab secret detection** to provide platform-level guardrails.
* **Push protection** to block secrets from entering remote repositories.
* **CI/CD security checks** to validate pipelines before deployment.
* **Dependency scanning** to find vulnerable libraries early.
* **Container scanning** to inspect images for leaked credentials.
* **Secret managers** to centralize and rotate secrets automatically.

**Security should be part of the development process rather than something you remember five minutes before deployment.**

Automation doesn't replace developers.

It simply gives them a safety net.

## The Mindset That Changed It for Me

After looking into all of this, I think the **“art”** part makes sense.

Protecting a secret is not about building an impossible-to-break system.

It is about **reducing exposure**.

You can't always guarantee that a secret will never leak. What you can do is reduce the number of places where it exists, limit who can access it, restrict what it can do, detect when it is exposed, and invalidate it quickly when necessary.

Perhaps the most important lesson is this:

> **Don't assume that a secret is safe because you hid it. Assume it can eventually leak and design your system so that one leaked secret does not become a compromise.**

That's what makes protecting secrets an art rather than simply a technical configuration.

## References

* GitGuardian — *State of Secrets Sprawl 2026*: https://github.com/GitGuardian
