---
title: "Digital Footprint Challenge: TryHackMe OSINT Write-Up"
date: 2026-02-08 14:32:57 +0100
categories: [Writeups, TryHackMe]
tags: [OSINT, digital-footprint, geolocation, web-archives, metadata, TryHackMe]
description: "A spoiler-filled walkthrough of the TryHackMe Digital Footprint challenge, using visual clues, web archives, landmark research, and document metadata."
---

The **Digital Footprint** challenge on TryHackMe is an OSINT investigation built around the fictional ACME Jet Solutions. Across four tasks, I used clues from a property photo, archived web records, a city landmark, and a leaked document to piece together the company's history and identify the final flag.

![Digital Footprint TryHackMe challenge](/assets/img/articles/digital-footprint-challenge.png)

> **Spoilers:** This walkthrough includes the investigation steps and flags for the challenge.

## Task 1: Locate the property

The first task asks where a photograph of a residential property was taken. Rather than trying to identify every detail in the image, I focused on its most distinctive clue: the **ADT Armed Response** security sign.

That clue points to South Africa. From there, checking the location of ADT's head office helped narrow down the city.

![Property photograph used in the location challenge](/assets/img/articles/digital-footprint-property-clue.jpeg)

**Flag:** `THM{Johannesburg}`

## Task 2: Check the website's history

ACME Jet Solutions claims it was founded in 2025, but the task asks when its website first appeared online. The **Internet Archive's Wayback Machine** can reveal earlier captures of a site and provide evidence that predates a company's public claim.

I searched for the challenge's domain in the archive and checked its earliest recorded capture. The timestamp in the archive record gives the requested date and time.

**Flag:** `THM{20160210224602}`

## Task 3: Identify the Dublin landmark

The next image shows a landmark beside a building connected to a country's independence. I first identified the landmark as **The Spire of Dublin**, then used its location to find the neighboring building: the **General Post Office (GPO)**.

![Landmark shown in the third OSINT task](/assets/img/articles/digital-footprint-landmark.jpeg)

**Flag:** `THM{General Post Office}`

## Task 4: Find the final flag

The final task centers on an office document and a reference to a video upload. Document properties can retain useful context, so I examined the provided file's metadata and found an internal username. Searching for the corresponding public YouTube profile connected that clue to the final flag.

![Document evidence used in the final task](/assets/img/articles/digital-footprint-document.png)

**Flag:** `THM{Y0u_f0und_7h3_fin4l_fl4g!}`

## What I learned

This room was a good reminder that OSINT is often about connecting small, public clues rather than relying on one source. A sign in a photograph, an archived timestamp, the location of a landmark, and document properties each provided a piece of the investigation.

When researching real people or organizations, keep the work within legal and ethical boundaries and avoid using discovered information to expose or target anyone.

*This write-up is adapted from [my original Medium article](https://medium.com/@maram.raboudi/digital-footprint-challenge-tryhackme-1698520a4125).*
