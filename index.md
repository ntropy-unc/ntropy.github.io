---
layout: default
---
### Welcome to UNC Ntropy
We are a band of UNC Chapel Hill students and noob security enthusiasts.
<div class="home">

  <h1 class="page-heading">Posts</h1>

  <ul class="post-list"> {% for post in site.posts %}
   <li style="list-style-type: none;">
   <h2> <a class="post-link" href="{{ post.url | prepend: site.baseurl }}">{{ post.title | escape }}</a> </h2>
      <span class="post-meta">{{ post.date | date: "%b %-d, %Y" }}</span>
   </li>
    {% endfor %}
</ul>
</div>

