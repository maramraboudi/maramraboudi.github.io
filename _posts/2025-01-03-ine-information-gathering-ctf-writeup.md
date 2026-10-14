---
layout: post
title: "Assessment Methodologies: Information Gathering CTF 1 Writeup"
date: 2025-01-03 15:35:15 +0000
categories: [Writeups, INE]
tags: [information-gathering, reconnaissance, nmap, web-enumeration, wordpress, robots-txt, eJPT]
description: "An INE Information Gathering CTF walkthrough covering robots.txt, service version detection, directory discovery, exposed backups, and website mirroring."
excerpt: "A reconnaissance-focused INE CTF walkthrough showing how public website information and exposed files reveal five flags."
---

> This walkthrough is for the INE training lab at `target.ine.local`. Only run reconnaissance or testing against systems you own or are explicitly authorized to assess.

## Introduction

I’m excited to share the solution to one of the early challenges I encountered while studying Information Gathering for the eJPT certification through INE. This walkthrough describes my approach to finding each flag.

### What is a CTF?

Capture the Flag (CTF) competitions combine problem-solving, cybersecurity challenges, and teamwork. This challenge focuses on information gathering and reconnaissance: examining a target website for useful information, exposed files, and misconfigurations that may inform a security assessment.

INE provides the training site at `http://target.ine.local`. The flags use an MD5-looking format.

## Flag 1: Search-engine instructions

The first hint points to `robots.txt`, a text file that website owners use to communicate crawler preferences. Its `Disallow` entries tell compliant crawlers which paths they should not index; these entries are not an access-control mechanism and do not make listed resources private.

I first opened the lab website:

![INE target homepage](/assets/img/articles/ine-ctf1-homepage.png)

Then I checked `robots.txt`:

![robots.txt on the target](/assets/img/articles/ine-ctf1-robots.png)

The file contained the first flag.

> **Flag 1:** `8155d9126fb24f2092855fbca6bea649`

## Flag 2: Identify the website and version

The next question asked which website software was running and which version. I used Nmap's default scripts and service-version detection:

```bash
nmap -sC -sV target.ine.local
```

- `-sC` runs Nmap's default set of NSE scripts.
- `-sV` attempts to identify service versions.

![Nmap version detection results](/assets/img/articles/ine-ctf1-nmap.png)

The scan output provided the information needed to answer the challenge.

> **Flag 2:** `c1e39ae6855349758f63ec15cbe8429e`

## Flag 3: Directory browsing

The hint suggested checking whether directory browsing revealed where files were stored. I used DirB to discover paths in the authorized lab:

```bash
dirb http://target.ine.local
```

DirB sends requests for words from a list and reports paths that return interesting responses:

![DirB directory discovery results](/assets/img/articles/ine-ctf1-dirb-results.png)

![Additional discovered paths](/assets/img/articles/ine-ctf1-dirb-files.png)

The results led to the `wp-content/uploads` directory:

![WordPress uploads directory listing](/assets/img/articles/ine-ctf1-uploads-index.png)

It contained a `flag.txt` file:

![Flag file in uploads](/assets/img/articles/ine-ctf1-flag3.png)

> **Flag 3:** `6ca785e9728243618484b02521a10f49`

## Flag 4: Backup file in the webroot

A backup file in a webroot can expose sensitive configuration details if it is publicly accessible. I searched for backup extensions with DirB:

```bash
dirb http://target.ine.local -w /usr/share/dirb/wordlists/big.txt -X .bak,.tar.gz,.zip,.sql,.bak.zip
```

Here, `-w` selects the wordlist and `-X` appends the listed file extensions to candidate names.

![Backup-file discovery scan](/assets/img/articles/ine-ctf1-backup-scan.png)

The scan found `wp-config.bak`. I requested the file with curl:

```bash
curl http://target.ine.local/wp-config.bak
```

![Exposed backup file](/assets/img/articles/ine-ctf1-backup-file.png)

The response contained the fourth flag:

![Flag 4](/assets/img/articles/ine-ctf1-flag4.png)

> **Flag 4:** `6912dbdbe9ff4c9f8e038a1b67fdb0a8`

## Flag 5: Mirroring the website

The final hint suggested mirroring the website. HTTrack can download site content for offline review. In the lab, I installed and ran it with:

```bash
sudo apt install httrack
httrack http://target.ine.local -O target.html
```

The `-O` option specifies the local output directory.

![Mirroring the target site](/assets/img/articles/ine-ctf1-httrack.png)

After the mirror completed, I searched the downloaded files:

![Files in the local website mirror](/assets/img/articles/ine-ctf1-mirror-files.png)

The flag was in `xmlrpc0db0.php`:

![Flag 5 in the mirrored file](/assets/img/articles/ine-ctf1-flag5.png)

> **Flag 5:** `8d93b2e60e7d46a395283f92c90c1a0d`

![CTF completion](/assets/img/articles/ine-ctf1-complete.png)

## Conclusion

This challenge demonstrates how methodical information gathering can reveal useful details without beginning with complex exploitation. Reviewing crawler directives, identifying service versions, discovering directories, checking for exposed backup files, and analyzing a local website mirror each contributed to finding a flag.

Whether you are new to CTFs or have more experience, each challenge is an opportunity to practice and improve. Keep reconnaissance within authorized environments, document what you discover, and use the findings to understand how exposed information could affect a real application.

---

*Originally published on [Medium](https://medium.com/@maram.raboudi/assessment-methodologies-information-gathering-ctf-1-writeup-21ad9807f9c9).*
