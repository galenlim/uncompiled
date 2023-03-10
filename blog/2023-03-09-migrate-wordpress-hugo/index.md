---
layout: post
title: Migrating A Side Hustle Website From Wordpress to Hugo
authors: galen
tags:
  - wordpress
  - hugo
  - static site generator
draft: true
---

Migrating a website from one platform to another can be a daunting task, but it is sometimes necessary to ensure that your website is optimized for better performance, more cost-effective, and allows for more flexibility. Recently, I decided to migrate one of my websites from WordPress to Hugo, and in this post, I'll share my experience.

Why?

My current website is based on WordPress which is open source. Unfortunately, the managed hosting platform I was using served it as a closed product. I could not add plugins or edit the theme without paying for their services.

At first, it seemed like a good idea to handle everything, but over time, I realized that it was becoming a burden. 

I wanted a platform that was more lightweight, easier to customize, and could help me achieve better Core Web Vitals scores, which are becoming increasingly important for SEO. 

After doing some research, I found that Hugo, a static site generator, was the perfect platform for my needs.

## Exporting WordPress Content

There are Wordpress plugins to faciliate a migration to Hugo, but as mentioned, I could not install plugins easily. Hence, these plugins were not an option for me,

The first step in the migration process was to export my WordPress content to XML format. WordPress provides an export feature that can export all your posts, pages, comments, custom post types, and other data in XML format. However, once I had the XML file, I needed to clean up the Markdown output, which was the most time-consuming stage of the process. Because every website is different, this is not a step that can be automated easily. I used ElementTree to parse the WordPress XML export to isolate one post for testing, then used regex to replace image links and fix any problems with the export.

Optimizing Images

I also took the opportunity to optimize my image size. I built a pipeline to download all my images and resize them to the correct dimensions using the ImageMagick tool. This saved a lot of space and helped to improve my website's load time.

Hugo Theme

I used the Doks Theme starter for Hugo, but had to customize it for my needs. Along the way, I picked up some Hugo templating skills. I found some helpful writeups on the internet that I referred to when planning this migration.

Bulk Editing with YQ

Bulk editing was easy using YQ, a YAML processor that allows for command-line editing of YAML files. It was great for making bulk changes to YAML front matter in Hugo.

Fixing Broken Links

Broken links were a significant problem after the migration, especially when I messed around with WordPress links. I used the Broken Link Checker Chrome extension to diagnose problems and fix broken links.

CSP Implementation

I implemented Content Security Policy (CSP) for my website, which is an added layer of security to prevent XSS attacks. I found some helpful references on the internet that helped me set up CSP in three steps.

Conclusion

Migrating a website is a challenging task, but it can be a rewarding experience when done right. In my case, I found that Hugo was the perfect platform for my needs. I hope this post has been helpful for anyone considering a similar migration.
