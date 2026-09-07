---

layout: post
title: "Authentication Is Not Security, That's When I Switched to Zero Trust"
date: 2026-04-26 18:00:00 +0100
categories: [Cybersecurity, Web Security]
tags: [zero-trust, authentication, authorization, web-security, application-security, jwt]
---

*"Most applications rely on authentication and call it secure. I did too, until I started breaking my own systems."*

That was one of those lessons that sounds obvious once you understand it, but isn't obvious when you're the person building the application.

I was working on a fairly simple web project. Authentication was already implemented, protected routes were in place, and everything looked fine from the outside.

Then I changed a request and sent it again.

The backend accepted it.

No second authorization check. No meaningful detection. Nothing stopped me.

That was the moment I realized I had made a dangerous assumption:

**I was treating a valid identity as proof that the request itself was trustworthy.**

It wasn't.

And that is what pushed me to start looking at application security differently.

## Authentication looked like security

For a long time, I thought secure access basically meant:

**User logs in → authentication succeeds → protected resources become available.**

It sounds reasonable.

The problem is that authentication answers only one thing: **who the user is**.

It does not determine what that user is allowed to access.

A user can be correctly authenticated and still be completely unauthorized to access a specific resource.

That distinction is where a lot of application security problems begin.

## The old assumption: once you're inside, you're trusted

A lot of systems still rely on assumptions like:

**The user is authenticated, so trust them.**

**The request came from an internal network, so it is probably safe.**

**The frontend hides this functionality, so regular users can't use it.**

**The session is valid, so the request must be legitimate.**

These assumptions become increasingly dangerous as applications move into cloud environments and become more distributed.

Users connect from different locations.

APIs communicate with other APIs.

Services interact across different networks and environments.

There may no longer be a meaningful "inside" and "outside."

This is where the idea of **Zero Trust** became much more interesting to me.

## What Zero Trust actually means

Zero Trust is often reduced to one sentence:

> **Never trust, always verify.**

It's a useful slogan, but it can also be misleading when taken too literally.

The real idea is to avoid **implicit trust**.

Access should be evaluated based on identity, authorization, the requested resource, and relevant context rather than being granted simply because a user has logged in or because the request came from a supposedly trusted network.

Authentication becomes one part of the access decision rather than the entire decision.

## Authentication ≠ Authorization ≠ Zero Trust

This was probably the most important distinction for me.

**Authentication** establishes identity.

**Authorization** determines what that identity is allowed to access.

**Zero Trust** builds a broader security model around these decisions by removing implicit trust and continuously evaluating whether access should be allowed.

A valid login therefore does not automatically mean that every action performed during that session is legitimate.

Once I started looking at applications this way, several weaknesses became much easier to spot.

## The first mistake: broken authorization

One of the simplest examples I encountered was an endpoint like:

```http
GET /api/users/101
Authorization: Bearer <user-token>
```

The backend verified that the user was authenticated.

What it did **not** verify was whether that user was actually allowed to access user `101`.

So I changed the identifier:

```http
GET /api/users/102
Authorization: Bearer <same-user-token>
```

The token was still valid.

The request was still authenticated.

And the backend still returned the resource.

That was the actual problem.

The security check answered:

> "Is this a real user?"

But it never checked whether that user had permission to access that specific object.

This is commonly associated with **Broken Object Level Authorization (BOLA)**.

The fix is straightforward in principle:

**Authorization must be enforced on the server for the specific resource being requested.**

Authentication alone is not enough.

## The second mistake: trusting the frontend

Another lesson came from role-based interfaces.

Imagine an application with an admin panel.

Normal users don't see the admin option.

It looks secure at first.

But hiding a button is a **user-interface decision**, not an authorization control.

If the backend does not enforce the same restriction, a user can simply try to access the endpoint or route directly.

For example:

```text
/admin
```

or:

```text
/api/admin/users
```

The frontend might never display those links.

That doesn't matter if the backend accepts the request.

The rule I follow now is simple:

> **The frontend can control the user experience. The backend must enforce security.**

UI visibility is not authorization.

## The third mistake: trusting JWTs too much

JWTs taught me another important lesson.

A token can look perfectly legitimate when you inspect its contents.

But decoding a JWT does not mean validating it.

A secure implementation needs to properly verify the token and validate the claims that matter to the application's security model.

Depending on the architecture, this can include:

* signature verification
* expiration
* issuer
* audience
* required claims
* permissions or scopes

The important point is that an application should never simply decode a token and assume that its contents are trustworthy.

That changed the way I think about JWTs.

I no longer see a token as proof that someone should automatically be allowed to perform an action.

It is one part of an authorization decision that still needs to be validated properly.

## The mindset change

After encountering these mistakes in my own projects, I started testing applications differently.

Instead of checking only whether authentication worked, I started testing what happened when I modified otherwise valid requests.

I changed object identifiers.

I called administrative endpoints directly.

I tested expired and invalid tokens.

I checked whether roles were enforced by the backend.

I looked at whether users could access resources belonging to someone else.

That was when security testing started becoming more interesting to me.

The important part was not simply getting past a login page.

It was finding situations where the application **trusted something that should have been verified**.

## Least privilege became much more important

Another part of the Zero Trust mindset that changed how I build applications is **least privilege**.

Users should only have the permissions they actually need.

Services should only have access to the resources they require.

APIs should expose only the operations that are necessary.

When a permission is unnecessary, there is little reason to grant it.

This becomes especially important as applications grow.

A small application may have only a few roles.

A larger environment can contain users, administrators, APIs, microservices, databases, cloud workloads, and third-party integrations communicating with each other.

The more components you add, the more dangerous unnecessary trust becomes.

## Internal does not automatically mean trusted

Another idea that stayed with me is that being "inside" a network should not automatically make a component trustworthy.

An internal service can still be compromised.

An authenticated user can still make an unauthorized request.

An API can still expose excessive permissions.

A workload can still be misconfigured.

Security therefore needs to exist at the resource and application level, not only at the network boundary.

That is especially important in modern environments where services are distributed across cloud and hybrid infrastructures.

## Logging is part of the security model

I also started taking logging much more seriously.

Strong authentication and authorization controls are valuable, but they become much harder to investigate when there is little visibility into what happened.

That doesn't mean logging every possible event without thinking about volume or usefulness.

It means capturing the security-relevant events that help with **detection, investigation, auditing, and response**.

Examples include:

* authentication failures
* privilege changes
* sensitive resource access
* administrative actions
* repeated authorization failures
* suspicious API activity

From a defensive perspective, prevention is only part of the job.

You also need enough visibility to understand what happened when something goes wrong.

## What Zero Trust looks like in practice

For me, Zero Trust became much less abstract once I applied it to ordinary application decisions.

Take a simple application with:

* a user dashboard
* an admin panel
* a backend API

A weak implementation might authenticate the user and then rely heavily on the existing session.

A stronger implementation evaluates each sensitive action based on the identity, token validity, permissions, resource ownership, and application policy.

For example, accessing a user's profile should involve more than checking whether the token is valid.

The backend should determine whether that identity is actually allowed to access that particular profile.

An administrative endpoint should require the appropriate privilege regardless of what the frontend displays.

A sensitive operation should be logged when the application needs that visibility.

The individual controls are not new.

The difference is that they are designed around the assumption that **trust must be earned rather than inherited**.

## Zero Trust is not a product

One thing I appreciate about Zero Trust is that you don't need a huge enterprise product to begin applying its principles.

It's not something you install with a single package.

You can start with a normal web application.

Enforce authorization on sensitive resources.

Validate tokens correctly.

Stop relying on the frontend for security.

Apply least privilege.

Separate components where appropriate.

Log security-relevant activity.

None of these require a complete enterprise Zero Trust architecture to be useful.

The important part is changing the way security decisions are made.

## What changed for me

Before this, I thought security was mostly about putting the right controls in place.

Authentication.

Protected routes.

Firewalls.

Tokens.

Permissions.

Those things still matter.

But I now see application security as much more about **challenging assumptions**.

A valid login does not make every request legitimate.

An internal network does not automatically make a service trustworthy.

A hidden button does not enforce authorization.

A decoded token is not necessarily a validated token.

And a request that looks normal can still be unauthorized.

That is why the Zero Trust concept stuck with me.

It changed the way I test the systems I build.

## The question I kept

There is really only one question from this whole experience that I still come back to:

> **What am I trusting that I haven't actually verified?**

That question has become useful far beyond authentication.

It applies to APIs, roles, services, tokens, network boundaries, and entire application architectures.

## Final thought

I'm not interested in Zero Trust because it's a popular security buzzword.

I'm interested in it because I learned the hard way that **authentication can succeed while security still fails**.

I've broken my own applications by changing identifiers, calling routes directly, and challenging assumptions that initially looked safe.

Those mistakes changed how I approach application security.

Now, instead of treating authentication as the finish line, I see it as the beginning of an access-control decision.

**Authentication tells me who is making the request.**

**Authorization determines what they can do.**

**Zero Trust removes the assumption that either one should automatically imply trust.**

And that is the mindset I want to carry into every system I build.
