---
layout: page
title: Events
category: Events
icon: fas fa-calendar-alt
order: 7
permalink: /events/
---

Stories from cybersecurity competitions, congresses, workshops, and the people I have met along the way.

{% assign event_posts = site.categories[page.category] | sort: 'date' | reverse %}

{% for post in event_posts %}
<article class="portfolio-card" markdown="1">

### [{{ post.title }}]({{ post.url | relative_url }})

<span class="text-muted">{{ post.date | date: '%B %-d, %Y' }}</span>

{{ post.excerpt }}

[Read the story]({{ post.url | relative_url }})

</article>
{% endfor %}
